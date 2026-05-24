# SOC Dashboard v2.0 — Phase 6 Single-Page Routing Architecture
# All metric logic delegated to: backend/, analytics/, visualization/, components/

import sys
import time
import json
import numpy as np
import networkx as nx
import streamlit as st
from copy import deepcopy
from pathlib import Path
from datetime import datetime

# ── Page config must be the first Streamlit call ───────────────────────────
st.set_page_config(
    page_title="Cyber MARL Threat Simulation Platform",
    page_icon="🛡️",
    layout="wide"
)

# ── CSS ─────────────────────────────────────────────────────────────────────
def load_css():
    try:
        with open("styles/theme.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        pass

load_css()

# ── Backend imports ──────────────────────────────────────────────────────────
sys.path.append(str(Path(__file__).resolve().parent / "src"))

from stable_baselines3 import PPO
from marlon.graph_env import GraphCyberEnv

from src.marlon.real_scan import scan_local_services
from src.marlon.dvwa_tester import login_dvwa

from backend.state_manager import initialize_session_state
from backend.reset_engine import reset_entire_simulation
from backend.simulation_engine import execute_simulation_step
from backend.graph_engine import generate_network_graph
from analytics.metrics_aggregator import aggregate_state_metrics
from analytics import build_timeline_df, build_mitre_table, export_soc_report
from analytics.ioc_engine import IOCEngine

# ── Component imports ────────────────────────────────────────────────────────
from components.kpi_cards import render_kpi_cards
from components.threat_panels import render_threat_hunt_panel, render_ioc_panel
from components.mitre_panels import render_mitre_panel
from components.executive_panels import render_executive_panel
from visualization.timeline_renderer import render_clean_timeline_section

# ── Session state initialization (canonical, single source of truth) ─────────
initialize_session_state(st)

# Persistent UI state
if "topology_fig" not in st.session_state:
    st.session_state.topology_fig = None
if "network_graph_fig" not in st.session_state:
    st.session_state.network_graph_fig = None
if "topology_fig_json" not in st.session_state:
    st.session_state.topology_fig_json = None
if "topology_nodes_snapshot" not in st.session_state:
    st.session_state.topology_nodes_snapshot = None
if "soc_trend_fig_json" not in st.session_state:
    st.session_state.soc_trend_fig_json = None
if "sidebar_summary" not in st.session_state:
    st.session_state.sidebar_summary = {"step": 0, "risk": 0.0, "reward": 0.0, "threat": "LOW"}
if "soc_metrics" not in st.session_state:
    # ensure a persistent copy exists to render from after simulation
    try:
        st.session_state.soc_metrics = st.session_state.simulation_state.get("metrics", {}).copy()
    except Exception:
        st.session_state.soc_metrics = {}

# ── Cached resource loading ──────────────────────────────────────────────────
@st.cache_resource
def load_models():
    attacker = PPO.load("models/ppo_attacker_graph")
    defender = PPO.load("models/ppo_defender_graph")
    return attacker, defender

@st.cache_resource
def load_env():
    return GraphCyberEnv()

attacker_model, defender_model = load_models()
env = load_env()

# ── DVWA login attempt (non-blocking) ────────────────────────────────────────
try:
    dvwa_logged_in = login_dvwa()
except Exception:
    dvwa_logged_in = False

# ── NetworkX graph (fixed layout) ───────────────────────────────────────────
G = nx.Graph()
for i in range(env.node_count):
    G.add_node(i)
for i in range(env.node_count):
    for j in range(i + 1, env.node_count):
        if env.graph[i, j] == 1:
            G.add_edge(i, j)

# Human-friendly node labels mapping. Node 1 carries the DVWA service in this
# six-node environment, so keep the service visible without inventing a node.
DEFAULT_NODE_LABELS = {
    0: "Workstation",
    1: "Firewall / DVWA",
    2: "Database",
    3: "Server",
    4: "DomainController",
    5: "SOC",
}

if "node_labels" not in st.session_state or not st.session_state.get("node_labels"):
    st.session_state.node_labels = DEFAULT_NODE_LABELS.copy()


def _ensure_topology_positions():
    """Create topology layout once and reuse it until reset."""
    if not st.session_state.get("node_labels"):
        st.session_state.node_labels = DEFAULT_NODE_LABELS.copy()
    if st.session_state.get("topology_positions"):
        return
    try:
        st.session_state.topology_positions = nx.spring_layout(G, seed=42, k=2.5)
    except Exception:
        st.session_state.topology_positions = {n: (0.0, 0.0) for n in G.nodes()}


_ensure_topology_positions()

# Topology render height.
TOPOLOGY_HEIGHT = 420


def build_plotly_topology(nodes_state: dict):
    """
    Build a lightweight Plotly representation of the topology for persistent rendering.
    """
    try:
        import plotly.graph_objects as go
    except Exception:
        return None

    _ensure_topology_positions()
    labels_map = st.session_state.get("node_labels", DEFAULT_NODE_LABELS)

    # Use persisted positions so layout is stable across reruns
    pos = st.session_state.get("topology_positions", {})
    edge_x = []
    edge_y = []
    for u, v in G.edges():
        x0, y0 = pos.get(u, (0.0, 0.0))
        x1, y1 = pos.get(v, (0.0, 0.0))
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode='lines',
        line=dict(width=3.0, color='#f97316'),
        hoverinfo='none'
    )

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    for i in range(env.node_count):
        x, y = pos.get(i, (0.0, 0.0))
        node_x.append(x)
        node_y.append(y)
        ninfo = nodes_state.get(i, {})
        status = ninfo.get('status', 'healthy')
        # larger sizes for clearer buttons and number-inside style
        if status == 'compromised':
            c = '#ef4444'; s = 56
        elif status == 'contained':
            c = '#facc15'; s = 46
        elif ninfo.get('defender_action') and ninfo.get('defender_action') != 'None':
            c = '#38bdf8'; s = 48
        else:
            c = '#22c55e'; s = 44
        node_color.append(c)
        node_size.append(s)
        node_text.append(f"{node_labels.get(i, G.nodes[i].get('label', f'Node {i}'))} — {status}")
    # Marker trace shows a small node index inside the circle; label trace
    # shows the friendly name above the circle so both are visible.
    marker_texts = [str(i) for i in range(env.node_count)]
    label_texts = [node_labels.get(i, G.nodes[i].get('label', f'Node {i}')) for i in range(env.node_count)]

    marker_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        marker=dict(size=node_size, color=node_color, line=dict(width=2, color='#0ea5e9')),
        text=marker_texts,
        textposition='middle center',
        textfont=dict(size=12, color='white'),
        hovertext=node_text,
        hoverinfo='text',
        showlegend=False
    )

    label_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='text',
        text=label_texts,
        textposition='top center',
        textfont=dict(size=12, color='white'),
        hoverinfo='skip',
        showlegend=False
    )

    fig = go.Figure(data=[edge_trace, marker_trace, label_trace])
    # Compute fixed axis ranges based on persisted positions so the
    # topology does not shift when Plotly recomputes autoscale on update.
    xs = [p[0] for p in pos.values()] if pos else [0.0]
    ys = [p[1] for p in pos.values()] if pos else [0.0]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    range_x = max_x - min_x if max_x != min_x else 1.0
    range_y = max_y - min_y if max_y != min_y else 1.0
    pad_x = range_x * 0.2
    pad_y = range_y * 0.2

    fig.update_layout(
        plot_bgcolor='#071028', paper_bgcolor='#071028',
        margin=dict(l=10, r=10, t=30, b=10),
        height=TOPOLOGY_HEIGHT,
        showlegend=False,
        autosize=True,
        uirevision='topology_v1',
        xaxis=dict(range=[min_x - pad_x, max_x + pad_x], showgrid=False, zeroline=False, visible=False, fixedrange=True),
        yaxis=dict(range=[min_y - pad_y, max_y + pad_y], showgrid=False, zeroline=False, visible=False, fixedrange=True)
    )
    return fig


def build_plotly_topology(nodes_state: dict):
    """Build a stable Plotly topology figure from canonical node state."""
    try:
        import plotly.graph_objects as go
    except Exception:
        return None

    _ensure_topology_positions()
    labels_map = st.session_state.get("node_labels", DEFAULT_NODE_LABELS)
    pos = st.session_state.get("topology_positions", {})

    edge_x = []
    edge_y = []
    for u, v in G.edges():
        x0, y0 = pos.get(u, (0.0, 0.0))
        x1, y1 = pos.get(v, (0.0, 0.0))
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=3.0, color="#f97316"),
        hoverinfo="none",
        showlegend=False,
    )

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    label_texts = []
    for i in range(env.node_count):
        x, y = pos.get(i, (0.0, 0.0))
        node_x.append(x)
        node_y.append(y)

        ninfo = nodes_state.get(i, {})
        status = ninfo.get("status", "healthy")
        if status == "compromised":
            color, size = "#ef4444", 56
        elif status == "contained":
            color, size = "#facc15", 46
        elif ninfo.get("defender_action") and ninfo.get("defender_action") != "None":
            color, size = "#38bdf8", 48
        else:
            color, size = "#22c55e", 44

        label = labels_map.get(i, f"Node {i}")
        node_color.append(color)
        node_size.append(size)
        label_texts.append(label)
        node_text.append(f"{label} - {status}")

    marker_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        marker=dict(size=node_size, color=node_color, line=dict(width=3, color="#0ea5e9")),
        text=[str(i) for i in range(env.node_count)],
        textposition="middle center",
        textfont=dict(size=13, color="white"),
        hovertext=node_text,
        hoverinfo="text",
        showlegend=False,
    )

    label_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="text",
        text=label_texts,
        textposition="top center",
        textfont=dict(size=13, color="white"),
        hoverinfo="skip",
        showlegend=False,
    )

    xs = [p[0] for p in pos.values()] if pos else [0.0]
    ys = [p[1] for p in pos.values()] if pos else [0.0]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    range_x = max_x - min_x if max_x != min_x else 1.0
    range_y = max_y - min_y if max_y != min_y else 1.0
    pad_x = range_x * 0.25
    pad_y = range_y * 0.25

    fig = go.Figure(data=[edge_trace, marker_trace, label_trace])
    fig.update_layout(
        plot_bgcolor="#071028",
        paper_bgcolor="#071028",
        margin=dict(l=10, r=10, t=30, b=10),
        height=TOPOLOGY_HEIGHT,
        showlegend=False,
        autosize=True,
        uirevision="topology_v1",
        xaxis=dict(range=[min_x - pad_x, max_x + pad_x], showgrid=False, zeroline=False, visible=False, fixedrange=True),
        yaxis=dict(range=[min_y - pad_y, max_y + pad_y], showgrid=False, zeroline=False, visible=False, fixedrange=True),
    )
    return fig


def _render_graph_image(slot, graph_bytes):
    """Render the PNG topology fallback into one placeholder update."""
    if slot is None or graph_bytes is None:
        return
    try:
        slot.image(graph_bytes, use_container_width=True)
    except TypeError:
        slot.image(graph_bytes, use_column_width=True)


def _safe_rerun():
    try:
        if hasattr(st, "rerun"):
            st.rerun()
        else:
            st.experimental_rerun()
    except Exception:
        try:
            st.experimental_rerun()
        except Exception:
            pass


def _persist_topology(nodes_state):
    fig = build_plotly_topology(nodes_state)
    if fig is not None:
        st.session_state.topology_fig = fig
    try:
        st.session_state.topology_nodes_snapshot = deepcopy(nodes_state)
    except Exception:
        st.session_state.topology_nodes_snapshot = nodes_state


def _persist_runtime_artifacts(state_obj):
    metrics_snapshot = state_obj.get("metrics", {})
    st.session_state.soc_metrics = metrics_snapshot.copy()
    st.session_state.live_feed = list(metrics_snapshot.get("event_logs", []))
    st.session_state.event_feed = st.session_state.live_feed
    st.session_state.timeline_events = list(state_obj.get("events", []))
    st.session_state.attack_history = st.session_state.timeline_events
    st.session_state.compromised_nodes = [
        node_id for node_id, node in state_obj.get("nodes", {}).items()
        if node.get("status") == "compromised"
    ]
    st.session_state.sidebar_summary = {
        "step": int(state_obj.get("simulation", {}).get("step", st.session_state.get("current_step", 0))),
        "risk": float(metrics_snapshot.get("risk_score", 0.0)),
        "reward": float(metrics_snapshot.get("total_reward", 0.0)),
        "threat": metrics_snapshot.get("threat_level", "LOW"),
    }
    trend_builder = globals().get("build_soc_trend_figure")
    st.session_state.soc_trend_fig = (
        trend_builder(metrics_snapshot) if callable(trend_builder) else None
    )
    st.session_state.trend_data = {
        "steps": list(metrics_snapshot.get("step_history", [])),
        "threats": list(metrics_snapshot.get("threat_history", [])),
        "compromises": list(metrics_snapshot.get("compromise_history", [])),
        "defenses": list(metrics_snapshot.get("defense_history", [])),
        "momentum": list(metrics_snapshot.get("momentum_history", [])),
    }
    try:
        st.session_state.attack_df = build_timeline_df(state_obj.get("events", []))
    except Exception:
        st.session_state.attack_df = None
    try:
        st.session_state.mitre_df = build_mitre_table(metrics_snapshot.get("technique_counts", {}))
    except Exception:
        st.session_state.mitre_df = None
    try:
        st.session_state.ioc_df = IOCEngine.generate_registry_df(state_obj.get("events", []))
    except Exception:
        st.session_state.ioc_df = None
    _persist_topology(state_obj.get("nodes", {}))
    try:
        graph_bytes = generate_network_graph(
            state_obj.get("nodes", {}), env.graph, env.node_types, env.node_count
        )
        if graph_bytes:
            st.session_state.network_graph_fig = graph_bytes
    except Exception:
        pass


if st.session_state.get("topology_fig") is None:
    _persist_topology(st.session_state.simulation_state.get("nodes", {}))

# ── Sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Simulation Controls")

speed = st.sidebar.slider(
    "Animation Speed",
    min_value=0.1,
    max_value=2.0,
    value=0.5,
    step=0.1,
    key="speed_slider_main"
)

run_button   = st.sidebar.button("▶ Start Simulation", key="run_simulation_button_main")
reset_button = st.sidebar.button("🔄 Reset Simulation", key="reset_simulation_button_main")

if reset_button:
    reset_entire_simulation(st, rerun=True)

if "soc_workspace" not in st.session_state:
    st.session_state.soc_workspace = "Overview"

if run_button:
    st.session_state.soc_workspace = "Overview"
    reset_entire_simulation(st, rerun=False)
    _ensure_topology_positions()
    st.session_state.simulation_started = True
    st.session_state.simulation_complete = False
    st.session_state.current_step = 0
    obs, _ = env.reset()
    st.session_state.sim_obs = obs
    state_for_start = st.session_state.simulation_state
    state_for_start["simulation"]["status"] = "running"
    state_for_start["simulation"]["running"] = True
    state_for_start["simulation"]["completed"] = False
    state_for_start["simulation"]["step"] = 0
    _persist_runtime_artifacts(state_for_start)

workspace = st.sidebar.radio(
    "SOC Workspace",
    ["Overview", "Threat Hunt", "IOC Intelligence", "MITRE Analytics", "Executive View"],
    key="soc_workspace"
)

# Show persisted sidebar summary (keeps values across rerenders)
sb = st.session_state.get("sidebar_summary", {"step": 0, "risk": 0.0, "reward": 0.0, "threat": "LOW"})
st.sidebar.markdown(
    f"**Step:** {sb.get('step', 0)} / {env.max_steps}  \n"
    f"**Risk:** {sb.get('risk', 0.0):.1f}%  \n"
    f"**Reward:** {sb.get('reward', 0.0):.2f}  \n"
    f"**Threat:** {sb.get('threat', 'LOW')}"
)

# Debug toggle (temporary): show session_state artifact presence in sidebar
if st.sidebar.checkbox("Show debug state (temp)", key="show_debug_state"):
    try:
        def _type_name(x):
            try:
                return type(x).__name__
            except Exception:
                return str(x)

        dbg = {
            "simulation_started": st.session_state.get("simulation_started"),
            "simulation_complete": st.session_state.get("simulation_complete"),
            "topology_fig_json_present": st.session_state.get("topology_fig_json") is not None,
            "topology_fig_present": st.session_state.get("topology_fig") is not None,
            "topology_nodes_snapshot_present": st.session_state.get("topology_nodes_snapshot") is not None,
            "topology_fig_json_type": _type_name(st.session_state.get("topology_fig_json")),
            "topology_nodes_snapshot_type": _type_name(st.session_state.get("topology_nodes_snapshot")),
            "soc_trend_fig_json_present": st.session_state.get("soc_trend_fig_json") is not None,
            "soc_trend_fig_present": st.session_state.get("soc_trend_fig") is not None,
            "soc_trend_fig_json_type": _type_name(st.session_state.get("soc_trend_fig_json")),
            "soc_trend_fig_type": _type_name(st.session_state.get("soc_trend_fig")),
            "network_graph_fig_present": st.session_state.get("network_graph_fig") is not None,
            "network_graph_fig_type": _type_name(st.session_state.get("network_graph_fig")),
            "attack_df_rows": len(st.session_state.get("attack_df", [])) if st.session_state.get("attack_df") is not None else 0,
        }
        st.sidebar.json(dbg)
    except Exception:
        st.sidebar.text("(debug info unavailable)")
# ── Alert fatigue guard ────────────────────────────────────────────────────────
if "alert_fatigue_score" not in st.session_state:
    st.session_state.alert_fatigue_score = 0

# ── Aliases for clean access ─────────────────────────────────────────────────
state      = st.session_state.simulation_state
metrics    = state["metrics"]
sim_status = state["simulation"]


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE RENDERERS  (one function per workspace — nothing renders globally)
# ═══════════════════════════════════════════════════════════════════════════════

def _render_header(metrics_local=None):
    """Shared header row: title + attacker / defender / engine pills.

    Accepts an optional `metrics_local` snapshot. Overview must render
    from persisted `st.session_state.soc_metrics` when available so the
    header is stable after the runtime loop completes.
    """
    if metrics_local is None:
        metrics_local = st.session_state.get("soc_metrics", {})

    defense_eff  = metrics_local.get("defense_effectiveness", 0.0)
    attack_stage = metrics_local.get("attack_stage", "Idle")

    risk_s = metrics_local.get("risk_score", 0.0)
    comp_count = metrics_local.get("compromised_count", 0)
    
    if st.session_state.get("simulation_complete", False):
        status_class = "success-banner"
        status_text = "🟢 SIMULATION COMPLETED — SOC ANALYTICS READY"
    elif not st.session_state.get("simulation_started", False):
        status_class = "standby-banner"
        status_text = "⚪ STANDBY MODE — Awaiting Simulation"
    elif risk_s >= 80.0 or comp_count >= 4:
        status_class = "active-banner"
        status_text = "🚨 CRITICAL BREACH ACTIVE — ENTERPRISE RESPONSE REQUIRED"
    else:
        status_class = "active-banner"
        status_text = "🔴 LIVE THREAT MONITORING ACTIVE — SIMULATING"

    top1, top2 = st.columns([3, 2])
    with top1:
        st.markdown("### 🛡️ CYBER MARL SOC PLATFORM")
        st.markdown(
            f'<div class="status-banner {status_class}">{status_text}</div>',
            unsafe_allow_html=True
        )

    with top2:
        sim_started = st.session_state.get("simulation_started", False)
        sim_complete = st.session_state.get("simulation_complete", False)

        # Attacker status — prefer final completed state over idle
        if sim_complete:
            att_color = "#38bdf8"
            att_bg = "rgba(56, 189, 248, 0.15)"
            att_text = f"ATTACKER: FINISHED ({attack_stage.upper()})"
        elif not sim_started:
            att_color = "#38bdf8"
            att_bg = "rgba(56, 189, 248, 0.15)"
            att_text = "ATTACKER: IDLE"
        else:
            stage_upper = attack_stage.upper()
            if attack_stage in ["Reconnaissance", "Discovery", "Scanning", "Idle"]:
                att_color = "#f59e0b"
                att_bg = "rgba(245, 158, 11, 0.15)"
                att_text = f"ATTACKER: {stage_upper}"
            else:
                att_color = "#ef4444"
                att_bg = "rgba(239, 68, 68, 0.15)"
                att_text = f"ATTACKER: {stage_upper}"

        # Defender status — prefer final completed state over idle
        if sim_complete:
            if defense_eff >= 60.0:
                def_color = "#10b981"
                def_bg = "rgba(16, 185, 129, 0.15)"
                def_text = f"DEFENDER: SECURED ({defense_eff:.1f}%)"
            else:
                def_color = "#ef4444"
                def_bg = "rgba(239, 68, 68, 0.15)"
                def_text = f"DEFENDER: COMPROMISED ({defense_eff:.1f}%)"
        elif not sim_started:
            def_color = "#38bdf8"
            def_bg = "rgba(56, 189, 248, 0.15)"
            def_text = "DEFENDER: STANDBY"
        else:
            if defense_eff >= 70.0:
                def_color = "#10b981"
                def_bg = "rgba(16, 185, 129, 0.15)"
                def_text = f"DEFENDER: ACTIVE ({defense_eff:.1f}%)"
            elif defense_eff >= 40.0:
                def_color = "#f59e0b"
                def_bg = "rgba(245, 158, 11, 0.15)"
                def_text = f"DEFENDER: ACTIVE ({defense_eff:.1f}%)"
            else:
                def_color = "#ef4444"
                def_bg = "rgba(239, 68, 68, 0.15)"
                def_text = f"DEFENDER: ALERT ({defense_eff:.1f}%)"

        # Engine status — prefer final completed state over idle
        if sim_complete:
            eng_color = "#10b981"
            eng_bg = "rgba(16, 185, 129, 0.15)"
            eng_text = " ENGINE: ANALYZED"
        elif not sim_started:
            eng_color = "#f59e0b"
            eng_bg = "rgba(245, 158, 11, 0.15)"
            eng_text = "ENGINE: READY"
        else:
            eng_color = "#10b981"
            eng_bg = "rgba(16, 185, 129, 0.15)"
            eng_text = " ENGINE: SIMULATING"

        st.markdown(
            f"""
            <div style="display:flex; gap:8px; justify-content:flex-end; align-items:center; height:auto; margin-top:0;padding-top:0;">
                <div style="background:{att_bg}; border:1px solid {att_color}; color:{att_color}; padding:6px 10px; border-radius:6px; font-size:11px; font-weight:700; text-align:center; flex:1; white-space:normal; overflow:visible; text-overflow:unset;" title="{att_text}">{att_text}</div>
                <div style="background:{def_bg}; border:1px solid {def_color}; color:{def_color}; padding:6px 10px; border-radius:6px; font-size:11px; font-weight:700; text-align:center; flex:1; white-space:normal; overflow:visible; text-overflow:unset;" title="{def_text}">{def_text}</div>
                <div style="background:{eng_bg}; border:1px solid {eng_color}; color:{eng_color}; padding:6px 10px; border-radius:6px; font-size:11px; font-weight:700; text-align:center; flex:1; white-space:normal; overflow:visible; text-overflow:unset;" title="{eng_text}">{eng_text}</div>
            </div>
            """,
            unsafe_allow_html=True
        )


def _render_top_kpis(metrics_local=None):
    """Four top-level KPI summary tiles.

    Accepts an optional `metrics_local` snapshot (preferred) so Overview
    rendering does not accidentally read the live `metrics` during reruns.
    """
    if metrics_local is None:
        metrics_local = st.session_state.get("soc_metrics", {})
    defense_eff  = metrics_local.get("defense_effectiveness", 0.0)
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)

    has_activity = (
        st.session_state.get("simulation_started", False)
        or st.session_state.get("simulation_complete", False)
        or bool(metrics_local.get("step_history"))
        or bool(metrics_local.get("event_logs"))
    )

    if not has_activity:
        kpi1.metric("Active Threats",    "0",       delta="Idle Monitoring")
        kpi2.metric("Compromised Nodes", "0",       delta="No Compromise")
        kpi3.metric("Defense Success",   "Standby", delta="Awaiting Simulation")
        kpi4.metric("Incident Status",   "NORMAL",  delta="System Idle")
    else:
        # Use provided snapshot
        m = metrics_local
        risk_s      = m.get("risk_score", 0.0)
        def_eff_str = f"{defense_eff:.1f}%"
        comp_count  = m.get("compromised_count", 0)
        if risk_s >= 80 or comp_count >= 5:
            inc_status = "ACTIVE INCIDENT" if risk_s >= 80 else "BREACH CONFIRMED"
            inc_delta  = "SOC Escalated" if risk_s >= 80 else "Critical Response"
        else:
            inc_status = "MONITORING"
            inc_delta  = "SOC Tracking"
        kpi1.metric("Active Threats",    str(m.get("critical_alerts", 0)),   delta="Threat Activity")
        kpi2.metric("Compromised Nodes", str(comp_count),                           delta="Hosts Impacted")
        kpi3.metric("Defense Success",   def_eff_str,                               delta="Active Defense")
        kpi4.metric("Incident Status",   inc_status,                                delta=inc_delta)


def _render_infra_status():
    """Real infrastructure service status (DVWA, MySQL, Nginx)."""
    services = scan_local_services()
    st.markdown("## Infrastructure Status")
    svc1, svc2, svc3 = st.columns(3)
    with svc1:
        if services["DVWA"]:
            st.success("DVWA Vulnerable Web App : ONLINE")
        else:
            st.error("DVWA Vulnerable Web App : OFFLINE")
    with svc2:
        if services["MySQL"]:
            st.success("MySQL Database : ONLINE")
        else:
            st.error("MySQL Database : OFFLINE")
    with svc3:
        if services["Nginx"]:
            st.success("Nginx Internal Service : ONLINE")
        else:
            st.error("Nginx Internal Service : OFFLINE")


def _render_event_console(logs: list, placeholder=None):
    """Live threat event console HTML block."""
    if placeholder is None:
        placeholder = st
    # Combine the title and feed into a single output so the placeholder
    # is not overwritten by multiple `placeholder.markdown` calls.
    feed_items = []
    # Prefer persisted live feed after simulation to avoid rerender loss
    if st.session_state.get("simulation_complete", False) and st.session_state.get("live_feed"):
        logs = st.session_state.live_feed

    if logs:
        for log in logs[:15]:
            cls = "standby-event"
            if any(kw in log for kw in ["ALERT", "CRITICAL", "Compromise", "Breach"]):
                cls = "critical-event"
            elif any(kw in log for kw in ["WARNING", "Recon", "Scan"]):
                cls = "warning-event"
            elif any(kw in log for kw in ["INFO", "Defender"]):
                cls = "info-event"
            feed_items.append(f'<div class="event-item {cls}">{log}</div>')
    elif st.session_state.get("simulation_started", False):
        feed_items.append('<div class="event-item info-event">[INFO] Simulation started...</div>')
    elif st.session_state.get("simulation_complete", False):
        feed_items.append('<div class="event-item info-event">[INFO] Simulation completed. No SOC events were retained.</div>')
    else:
        feed_items.append('<div class="event-item info-event">[INFO] SOC monitoring initialized successfully</div>')
        feed_items.append('<div class="event-item standby-event">[STANDBY] Awaiting attacker simulation trigger</div>')

    feed_html = (
        '<div class="section-header"><h3> Live SOC Event Feed</h3></div>'
        f'<div class="event-console"><div class="live-feed-container">{"".join(feed_items)}</div></div>'
    )
    placeholder.markdown(feed_html, unsafe_allow_html=True)


def _render_event_console(logs: list, placeholder=None):
    """Render feed entries inside a stable scrollable card."""
    if placeholder is None:
        placeholder = st
    if st.session_state.get("simulation_complete", False) and st.session_state.get("live_feed"):
        logs = st.session_state.live_feed

    feed_items = []
    if logs:
        for log in logs[:30]:
            cls = "standby-event"
            if any(kw in log for kw in ["ALERT", "CRITICAL", "Compromise", "Breach"]):
                cls = "critical-event"
            elif any(kw in log for kw in ["WARNING", "Recon", "Scan"]):
                cls = "warning-event"
            elif any(kw in log for kw in ["INFO", "Defender"]):
                cls = "info-event"
            feed_items.append(f'<div class="event-item {cls}">{log}</div>')
    elif st.session_state.get("simulation_started", False):
        feed_items.append('<div class="event-item info-event">[INFO] Simulation started...</div>')
    elif st.session_state.get("simulation_complete", False):
        feed_items.append('<div class="event-item info-event">[INFO] Simulation completed. No SOC events were retained.</div>')
    else:
        feed_items.append('<div class="event-item info-event">[INFO] SOC monitoring initialized successfully</div>')
        feed_items.append('<div class="event-item standby-event">[STANDBY] Awaiting attacker simulation trigger</div>')

    placeholder.markdown(
        f'<div class="event-console"><div class="live-feed-container">{"".join(feed_items)}</div></div>',
        unsafe_allow_html=True,
    )


def _render_soc_trend_chart(placeholder=None, key=None, metrics_local=None):
    """Render the SOC performance trend chart using stored metrics history.

    Accepts `metrics_local` snapshot to render from persisted state after
    simulation completes.
    """
    if placeholder is None:
        placeholder = st

    m = metrics_local if metrics_local is not None else st.session_state.get("soc_metrics", {})
    step_hist   = m.get("step_history", [])
    threat_hist = m.get("threat_history", [])
    comp_hist   = m.get("compromise_history", [])
    def_hist    = m.get("defense_history", [])
    mom_hist    = m.get("momentum_history", [])

    n = min(len(step_hist), len(threat_hist), len(comp_hist))
    if n < 2:
        placeholder.markdown('<div class="empty-placeholder">&#9654; SOC Trend data will appear here once the simulation generates event history.</div>', unsafe_allow_html=True)
        return

    import plotly.express as px
    import pandas as pd

    chart_data = {
        "Step":              step_hist[:n],
        "Critical Alerts":   threat_hist[:n],
        "Compromised Nodes": comp_hist[:n],
    }
    def_n = min(n, len(def_hist))
    if def_n > 0:
        chart_data["Successful Defenses"] = def_hist[:def_n] + [None] * (n - def_n)
    mom_n = min(n, len(mom_hist))
    if mom_n > 0:
        chart_data["Threat Momentum"] = mom_hist[:mom_n] + [None] * (n - mom_n)

    df = pd.DataFrame(chart_data)
    value_vars = [c for c in ["Critical Alerts", "Compromised Nodes",
                              "Successful Defenses", "Threat Momentum"]
                  if c in df.columns and df[c].notna().any()]
    if not value_vars:
        placeholder.markdown('<div class="empty-placeholder">&#9654; SOC Trend chart is waiting for live metrics data.</div>', unsafe_allow_html=True)
        return

    df_melt = df.melt(id_vars=["Step"], value_vars=value_vars,
                      var_name="Metric", value_name="Value")
    fig_chart = px.line(
        df_melt, x="Step", y="Value", color="Metric",
        title="SOC Threat Analytics & Performance Trends",
        markers=True,
        color_discrete_map={
            "Critical Alerts":    "#ef4444",
            "Compromised Nodes":  "#eab308",
            "Successful Defenses":"#22c55e",
            "Threat Momentum":    "#0ea5e9"
        }
    )
    fig_chart.update_layout(
        autosize=True,
        paper_bgcolor="#071028", plot_bgcolor="#071028",
        font_color="white",
        legend=dict(orientation="h", yanchor="top", y=-0.15,
                    xanchor="center", x=0.5, font=dict(size=10)),
        xaxis=dict(showgrid=True, gridcolor="#1e293b", fixedrange=False, rangemode="tozero",range=[-0.5, len(step_hist) + 0.5]),
        yaxis=dict(showgrid=True, gridcolor="#1e293b", fixedrange=False, rangemode="tozero", range=[0, 60]),
        margin=dict(l=40, r=20, t=50, b=60), height=550,
        transition={'duration': 0},
        uirevision='soc_trend_v1'
    )
    if key is not None:
        placeholder.plotly_chart(fig_chart, use_container_width=True,
                                  config={"responsive": True,"scrollZoom": False}, key=key)
    else:
        placeholder.plotly_chart(fig_chart, use_container_width=True,
                                  config={"responsive": True,"scrollZoom": False})


def build_soc_trend_figure(metrics_local=None):
    """Build and return a SOC trend Plotly figure (or None if insufficient data)."""
    m = metrics_local if metrics_local is not None else st.session_state.get("soc_metrics", {})
    step_hist = m.get("step_history", [])
    threat_hist = m.get("threat_history", [])
    comp_hist = m.get("compromise_history", [])
    def_hist = m.get("defense_history", [])
    mom_hist = m.get("momentum_history", [])

    n = min(len(step_hist), len(threat_hist), len(comp_hist))
    if n < 2:
        return None

    try:
        import plotly.express as px
        import pandas as pd
    except Exception:
        return None

    chart_data = {
        "Step": step_hist[:n],
        "Critical Alerts": threat_hist[:n],
        "Compromised Nodes": comp_hist[:n],
    }
    def_n = min(n, len(def_hist))
    if def_n > 0:
        chart_data["Successful Defenses"] = def_hist[:def_n] + [None] * (n - def_n)
    mom_n = min(n, len(mom_hist))
    if mom_n > 0:
        chart_data["Threat Momentum"] = mom_hist[:mom_n] + [None] * (n - mom_n)

    df = pd.DataFrame(chart_data)
    value_vars = [c for c in ["Critical Alerts", "Compromised Nodes",
                              "Successful Defenses", "Threat Momentum"]
                  if c in df.columns and df[c].notna().any()]
    if not value_vars:
        return None

    df_melt = df.melt(id_vars=["Step"], value_vars=value_vars,
                      var_name="Metric", value_name="Value")
    fig_chart = px.line(
        df_melt, x="Step", y="Value", color="Metric",
        title="SOC Threat Analytics & Performance Trends",
        markers=True,
        color_discrete_map={
            "Critical Alerts":    "#ef4444",
            "Compromised Nodes":  "#eab308",
            "Successful Defenses":"#22c55e",
            "Threat Momentum":    "#0ea5e9"
        }
    )
    fig_chart.update_layout(
        autosize=True,
        paper_bgcolor="#071028", plot_bgcolor="#071028",
        font_color="white",
        legend=dict(orientation="h", yanchor="top", y=-0.15,
                    xanchor="center", x=0.5, font=dict(size=10)),
        xaxis=dict(showgrid=True, gridcolor="#1e293b", fixedrange=False, rangemode="tozero",range=[-0.5, len(step_hist) + 0.5]),
        yaxis=dict(showgrid=True, gridcolor="#1e293b", fixedrange=False, rangemode="tozero",range=[0, 60]),
        margin=dict(l=40, r=20, t=50, b=60), height=420,
        transition={'duration': 0},
        uirevision='soc_trend_v1'
    )
    return fig_chart


def render_overview_runtime_page():
    """Overview workspace — renders all top-level SOC components exactly once."""
    # Use persisted snapshot for Overview rendering so UI doesn't depend on live `metrics`
    metrics_local = st.session_state.get("soc_metrics", state.get("metrics", {}))

    # 1) Header
    header_container = st.container()
    with header_container:
        _render_header(metrics_local=metrics_local)

    # 2) Top KPI cards
    top_kpi_container = st.container()
    with top_kpi_container:
        _render_top_kpis(metrics_local=metrics_local)

    # 3) Infrastructure status
    infra_container = st.container()
    with infra_container:
        _render_infra_status()

    # 4) Network Topology (stable container - render into a single slot so
    #    updates overwrite the same element and do not append multiple charts)
    graph_container = st.container()
    with graph_container:
        st.markdown("##  Network Topology")
        # dedicated slot inside the container to update the chart in-place
        graph_slot = st.container()
        # Debug: print presence of persisted artifacts and current sim state
        try:
            print(
                "[DEBUG UI] simulation_started=", st.session_state.get("simulation_started", False),
                "topology_fig_exists=", (st.session_state.get("topology_fig_json") is not None) or (st.session_state.get("topology_fig") is not None),
                "topology_nodes_snapshot=", st.session_state.get("topology_nodes_snapshot") is not None,
                "network_graph_fig_exists=", st.session_state.get("network_graph_fig") is not None,
            )
        except Exception:
            pass
        # Render the same PNG snapshot path before and after completion.
        is_running = st.session_state.get("simulation_started", False)

        graph_bytes = st.session_state.get("network_graph_fig")
        if graph_bytes is None and not is_running and st.session_state.get("simulation_complete", False):
            nodes_snap = st.session_state.get("topology_nodes_snapshot") or state.get("nodes", {})
            try:
                graph_bytes = generate_network_graph(
                    nodes_snap, env.graph, env.node_types, env.node_count
                )
                st.session_state.network_graph_fig = graph_bytes
            except Exception:
                graph_bytes = None

        if graph_bytes is not None:
            _render_graph_image(graph_slot, graph_bytes)
        elif not is_running:
            graph_slot.markdown(
                '<div class="graph-card" style="display:flex; align-items:center; justify-content:center; min-height:120px;">'
                '<div style="text-align:center; color:#cbd5e1; font-size:1rem;">&#9654; Click "Start Simulation" to load the interactive network topology.</div>'
                '</div>', unsafe_allow_html=True)
        else:
            graph_slot.markdown(f'<div style="min-height:{TOPOLOGY_HEIGHT}px"></div>', unsafe_allow_html=True)

    # spacer removed to avoid an extra separator between graph and feed

    # 5) Live SOC Event Feed (render into an update slot so repeated
    #    simulation updates replace the content instead of appending)
    feed_container = st.container()
    with feed_container:
        feed_slot = st.container()
        _render_event_console(metrics_local.get("event_logs", []), placeholder=feed_slot)

    # 6) SOC trend chart (render into slot for in-place updates)
    chart_container = st.container()
    with chart_container:
        chart_slot = st.container()
        # Render static SOC trend chart only when a simulation is not active.
        # Prefer a persisted Plotly figure if available (persisted after run).
        if not st.session_state.get("simulation_started", False):
            # Prefer JSON rehydration for stability across reruns
            rehydrated = None
            if st.session_state.get("soc_trend_fig_json") is not None:
                try:
                    import plotly.graph_objects as go
                    rehydrated = go.Figure(st.session_state.soc_trend_fig_json)
                except Exception:
                    rehydrated = None

            if rehydrated is not None:
                try:
                    chart_slot.plotly_chart(rehydrated, use_container_width=True, config={"responsive": True}, key="overview_soc_trend_chart_static")
                except Exception:
                    _render_soc_trend_chart(placeholder=chart_slot, key="overview_soc_trend_chart_static", metrics_local=metrics_local)
            elif st.session_state.get("soc_trend_fig") is not None:
                try:
                    chart_slot.plotly_chart(
                        st.session_state.soc_trend_fig,
                        use_container_width=True,
                        config={"responsive": True},
                        key="overview_soc_trend_chart_static"
                    )
                except Exception:
                    _render_soc_trend_chart(placeholder=chart_slot, key="overview_soc_trend_chart_static", metrics_local=metrics_local)
            else:
                _render_soc_trend_chart(placeholder=chart_slot, key="overview_soc_trend_chart_static", metrics_local=metrics_local)
        else:
            chart_slot.markdown(
                '<div class="empty-placeholder">&#9654; SOC Trend data will appear here once live metrics are generated.</div>',
                unsafe_allow_html=True
            )
        try:
            print(
                "[DEBUG UI] soc_trend_fig_exists=", st.session_state.get("soc_trend_fig") is not None,
                "attack_df_exists=", st.session_state.get("attack_df") is not None
            )
        except Exception:
            pass

    # 7) Compact Attack Timeline preview — create a table slot the runtime
    #    loop will update in-place. This preserves horizontal scrolling and
    #    ensures the timeline appears live during the simulation.
    timeline_table_slot = st.container()
    with timeline_table_slot.container():
        st.markdown("### Attack Timeline Log")
        # Prefer persisted attack dataframe after simulation; otherwise
        # build a lightweight preview from the current in-memory events.
        if st.session_state.get("attack_df") is not None:
            timeline_df = st.session_state.attack_df
        else:
            timeline_df = build_timeline_df(state.get("events", []))

        display_columns = [
            "Event ID", "Time", "Stage", "Severity", "Technique", "Target Node",
            "Source Node", "CVE", "Actor", "Confidence", "Status"
        ]

        if timeline_df is not None and not timeline_df.empty:
            display_df = timeline_df[display_columns].reset_index(drop=True)
            # If the full persisted table exists, show it; otherwise show a
            # compact preview (last 10 events) during the run.
            # Persisted full attack timeline
            if st.session_state.get("attack_df") is not None:

                st.markdown(
                    """
                    <div class="soc-card soc-table-card attack-table-card">
                    """,
                    unsafe_allow_html=True
                )

                st.dataframe(
                    display_df,
                    use_container_width=True,
                    height=420,
                    hide_index=True,
                    column_config={
                        "Timestamp": st.column_config.TextColumn(width="medium"),
                        "Stage": st.column_config.TextColumn(width="medium"),
                        "Technique": st.column_config.TextColumn(width="medium"),
                        "Severity": st.column_config.TextColumn(width="small"),
                        "Target": st.column_config.TextColumn(width="medium"),
                        "Description": st.column_config.TextColumn(width="large"),
                    }
                )

                st.markdown("</div>", unsafe_allow_html=True)

                # Downloads
                try:
                    csv_data = export_soc_report(timeline_df)
                except Exception:
                    csv_data = None

                export_state = {
                    "soc_metrics": st.session_state.get("soc_metrics", {}),
                    "sidebar_summary": st.session_state.get("sidebar_summary", {}),
                    "attack_timeline": timeline_df.to_dict(orient="records"),
                    "live_feed": st.session_state.get("live_feed", [])
                }

                def _safe_serialize(obj, _seen=None):
                    if _seen is None:
                        _seen = set()
                    oid = id(obj)
                    if oid in _seen:
                        return "<circular>"
                    # primitives
                    if obj is None or isinstance(obj, (str, int, float, bool)):
                        return obj
                    # sequences
                    if isinstance(obj, (list, tuple, set)):
                        _seen.add(oid)
                        res = [_safe_serialize(v, _seen) for v in obj]
                        _seen.discard(oid)
                        return res
                    # dict
                    if isinstance(obj, dict):
                        _seen.add(oid)
                        out = {}
                        for k, v in obj.items():
                            try:
                                key = str(k)
                            except Exception:
                                key = "<key>"
                            out[key] = _safe_serialize(v, _seen)
                        _seen.discard(oid)
                        return out
                    # pandas / numpy
                    try:
                        import pandas as pd
                        import numpy as np
                        if isinstance(obj, pd.DataFrame):
                            return obj.to_dict(orient="records")
                        if isinstance(obj, pd.Series):
                            return obj.tolist()
                        if isinstance(obj, np.ndarray):
                            return obj.tolist()
                    except Exception:
                        pass
                    # bytes
                    if isinstance(obj, (bytes, bytearray)):
                        try:
                            import base64
                            return base64.b64encode(bytes(obj)).decode("ascii")
                        except Exception:
                            return "<binary>"
                    # datetime
                    try:
                        from datetime import datetime as _dt
                        if isinstance(obj, _dt):
                            return obj.isoformat()
                    except Exception:
                        pass
                    # fallback to string
                    try:
                        return str(obj)
                    except Exception:
                        return "<unserializable>"

                json_data = json.dumps(_safe_serialize(export_state), indent=2)

                dl_col1, dl_col2 = st.columns(2)
                with dl_col1:
                    if csv_data is not None:
                        st.download_button(label="📥 Download CSV SOC Report", data=csv_data, file_name="soc_attack_timeline.csv", mime="text/csv", key="download_soc_report_overview")
                    else:
                        st.download_button(label="📥 Download JSON Telemetry", data=json_data, file_name="soc_telemetry_dump.json", mime="application/json", key="download_soc_json_overview")
                with dl_col2:
                    st.download_button(label="📥 Download JSON Telemetry", data=json_data, file_name="soc_telemetry_dump.json", mime="application/json", key="download_soc_json_overview_2")
            else:
                preview_df = display_df.tail(10)
                st.markdown('<div class="soc-card soc-table-card">', unsafe_allow_html=True)
                st.dataframe(preview_df, use_container_width=False, width=1200, height=220, hide_index=True)
                st.markdown('</div>', unsafe_allow_html=True)
                # Allow downloading a preview JSON while running (CSV requires full report builder)
                try:
                    preview_export = {
                        "attack_timeline_preview": preview_df.to_dict(orient="records"),
                        "live_feed": st.session_state.get("live_feed", [])
                    }
                    preview_json = json.dumps(_safe_serialize(preview_export), indent=2)
                    st.download_button(label="📥 Download Preview JSON", data=preview_json, file_name="soc_attack_timeline_preview.json", mime="application/json", key="download_soc_preview_json_overview")
                except Exception:
                    pass
        else:
            st.markdown('<div class="empty-placeholder">&#9654; Attack timeline will appear here once events are generated.</div>', unsafe_allow_html=True)

    # Return containers and slots so the simulation runtime can update them directly
    return header_container, top_kpi_container, infra_container, graph_slot, feed_slot, chart_slot, timeline_table_slot


def render_overview_page():
    """Overview workspace rendered only from persisted session state."""
    metrics_local = st.session_state.get("soc_metrics", {})

    with st.container():
        _render_header(metrics_local=metrics_local)

    with st.container():
        _render_top_kpis(metrics_local=metrics_local)

    with st.container():
        _render_infra_status()

    with st.container():
        st.markdown("## Network Topology")
        graph_bytes = st.session_state.get("network_graph_fig")

        if graph_bytes is not None:
            try:
                st.image(graph_bytes, use_container_width=True)
            except TypeError:
                st.image(graph_bytes, use_column_width=True)
        elif st.session_state.get("simulation_started", False) or st.session_state.get("simulation_complete", False):
            nodes_snap = st.session_state.get("topology_nodes_snapshot") or state.get("nodes", {})
            try:
                graph_bytes = generate_network_graph(
                    nodes_snap, env.graph, env.node_types, env.node_count
                )
                st.session_state.network_graph_fig = graph_bytes
                try:
                    st.image(graph_bytes, use_container_width=True)
                except TypeError:
                    st.image(graph_bytes, use_column_width=True)
            except Exception:
                st.markdown('<div class="empty-placeholder">&#9654; Generating topology...</div>', unsafe_allow_html=True)
        else:
            st.markdown(
                '<div class="graph-card" style="display:flex; align-items:center; justify-content:center; min-height:420px;">'
                '<div style="text-align:center; color:#cbd5e1; font-size:1rem;">&#9654; Click "Start Simulation" to load the network topology.</div>'
                '</div>',
                unsafe_allow_html=True,
            )

    with st.container():
        st.markdown("## Live SOC Event Feed")
        _render_event_console(st.session_state.get("live_feed", metrics_local.get("event_logs", [])))

    with st.container():
        st.markdown("## SOC Trend Analytics")
        trend_fig = st.session_state.get("soc_trend_fig")
        if trend_fig is not None:
            st.plotly_chart(
                trend_fig,
                use_container_width=True,
                config={"responsive": True},
                key="overview_soc_trend_persistent",
            )
        else:
            _render_soc_trend_chart(
                key="overview_soc_trend_chart_static",
                metrics_local=metrics_local,
            )


def render_threat_hunt_page():
    """Threat Hunt workspace."""
    # Render the Threat Hunt summary panel (metrics, observed techniques, stages, actions)
    render_threat_hunt_panel(state)
    # Then render the clean timeline section for chronological event view
    render_clean_timeline_section(state)


def render_ioc_page():
    """IOC Intelligence workspace."""
    render_ioc_panel(state)


def render_mitre_page():
    """MITRE Analytics workspace."""
    render_mitre_panel(state)


def render_executive_page():
    """Executive View workspace."""
    render_executive_panel(state)


# Simulation loop executes after the workspace is rendered so Overview placeholders are created before updates.


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLE ROUTING BLOCK  — exactly one page renders per Streamlit run
# ═══════════════════════════════════════════════════════════════════════════════

# Re-alias in case reset was called during the run loop
state   = st.session_state.simulation_state
metrics = state["metrics"]

page_placeholders = None
if workspace == "Overview":
    # Overview should render the persisted-only view (no live timeline)
    page_placeholders = render_overview_page()
elif workspace == "Threat Hunt":
    render_threat_hunt_page()
elif workspace == "IOC Intelligence":
    render_ioc_page()
elif workspace == "MITRE Analytics":
    render_mitre_page()
elif workspace == "Executive View":
    render_executive_page()


def _advance_simulation_one_step():
    state_obj = st.session_state.simulation_state
    step = int(st.session_state.get("current_step", 0))

    if step >= env.max_steps:
        state_obj["simulation"]["status"] = "completed"
        state_obj["simulation"]["running"] = False
        state_obj["simulation"]["completed"] = True
        st.session_state.simulation_started = False
        st.session_state.simulation_complete = True
        _persist_runtime_artifacts(state_obj)
        _safe_rerun()
        return

    obs = st.session_state.get("sim_obs")
    if obs is None:
        obs, _ = env.reset()

    state_obj["simulation"]["status"] = "running"
    state_obj["simulation"]["running"] = True
    state_obj["simulation"]["completed"] = False

    obs = execute_simulation_step(
        step=step,
        state=state_obj,
        env=env,
        attacker_model=attacker_model,
        defender_model=defender_model,
        obs=obs,
        G=G,
        dvwa_logged_in=dvwa_logged_in,
    )

    aggregate_state_metrics(state_obj)
    st.session_state.sim_obs = obs
    st.session_state.current_step = step + 1
    state_obj["simulation"]["step"] = step + 1
    _persist_runtime_artifacts(state_obj)

    if step + 1 >= env.max_steps:
        state_obj["simulation"]["status"] = "completed"
        state_obj["simulation"]["running"] = False
        state_obj["simulation"]["completed"] = True
        st.session_state.simulation_started = False
        st.session_state.simulation_complete = True
        _persist_runtime_artifacts(state_obj)
    else:
        time.sleep(speed)

    _safe_rerun()


if st.session_state.get("simulation_started", False):
    _advance_simulation_one_step()

if False and run_button:
    # Simulation state was reset before rendering; just start the runtime loop now.
    state   = st.session_state.simulation_state
    metrics = state["metrics"]
    state["simulation"]["status"]  = "running"
    state["simulation"]["running"] = True

    # Reset env observation
    obs, _ = env.reset()

    # Unpack the container/slot references returned by the page renderer
    header_container = top_kpi_container = infra_container = None
    graph_slot = feed_slot = chart_slot = timeline_container = None
    if page_placeholders is not None:
        header_container, top_kpi_container, infra_container, graph_slot, feed_slot, chart_slot, timeline_container = page_placeholders

    # Use a stable topology key for the runtime display so the post-run
    # static render targets the same Streamlit element.
    topology_key = "overview_topology"
    # Debug: log the topology key to the server console to trace duplicate ID issues
    try:
        print(f"[DEBUG] topology_key={topology_key}")
    except Exception:
        pass

    # Prepare a mutable Plotly FigureWidget so we can update traces
    # in-place during the simulation loop without re-creating chart
    # elements on every iteration (prevents duplicate element IDs).
    fig_widget = None
    try:
        import plotly.graph_objects as go
        can_make_widget = True
    except Exception:
        go = None
        can_make_widget = False

    if (not USE_PNG_NETWORK_TOPOLOGY) and can_make_widget and graph_slot is not None:
        try:
            init_fig = build_plotly_topology(state.get("nodes", {}))
        except Exception:
            init_fig = None

        if init_fig is not None:
            try:
                fig_widget = go.FigureWidget(init_fig)
                # Display the widget once; we'll mutate `fig_widget` in-place
                graph_slot.plotly_chart(fig_widget, use_container_width=True,
                                        config={"displayModeBar": False, "responsive": True},
                                        key=topology_key)
                # persist the original fig for post-run rendering as JSON
                try:
                    st.session_state.topology_fig_json = init_fig.to_dict()
                    st.session_state.topology_fig = None
                except Exception:
                    st.session_state.topology_fig = init_fig
                    st.session_state.topology_fig_json = None
                # snapshot node states so we can rebuild the topology reliably
                try:
                    st.session_state.topology_nodes_snapshot = deepcopy(state.get("nodes", {}))
                except Exception:
                    st.session_state.topology_nodes_snapshot = state.get("nodes", {})
            except Exception:
                fig_widget = None

    # Prepare SOC trend FigureWidget for in-place updates during simulation
    soc_fig_widget = None
    if can_make_widget and chart_slot is not None:
        try:
            soc_key = "overview_soc_trend"
            soc_init_fig = build_soc_trend_figure(metrics)
        except Exception:
            soc_init_fig = None

        if soc_init_fig is not None:
            try:
                soc_fig_widget = go.FigureWidget(soc_init_fig)
                chart_slot.plotly_chart(soc_fig_widget, use_container_width=True,
                                        config={"responsive": True}, key=soc_key)
                # persist SOC trend as JSON so we can rehydrate after reruns
                try:
                    st.session_state.soc_trend_fig_json = soc_init_fig.to_dict()
                    st.session_state.soc_trend_fig = None
                except Exception:
                    st.session_state.soc_trend_fig = soc_init_fig
                    st.session_state.soc_trend_fig_json = None
            except Exception:
                soc_fig_widget = None

    for step in range(env.max_steps):
        obs = execute_simulation_step(
            step=step,
            state=state,
            env=env,
            attacker_model=attacker_model,
            defender_model=defender_model,
            obs=obs,
            G=G,
            dvwa_logged_in=dvwa_logged_in
        )

        aggregate_state_metrics(state)

        risk_s  = metrics.get("risk_score", 0.0)
        rew_val = metrics.get("total_reward", 0.0)
        thr_lvl = metrics.get("threat_level", "LOW")

        # Persist sidebar summary and soc metrics so they survive rerenders
        st.session_state.sidebar_summary = {
            "step": step + 1,
            "risk": float(risk_s),
            "reward": float(rew_val),
            "threat": thr_lvl,
        }
        st.session_state.soc_metrics = metrics.copy()
        st.session_state.live_feed = metrics.get("event_logs", [])

        # Update visible sidebar summary
        try:
            timer_placeholder.markdown(
                f"**Step:** {st.session_state.sidebar_summary['step']} / {env.max_steps}  \n"
                f"**Risk:** {st.session_state.sidebar_summary['risk']:.1f}%  \n"
                f"**Reward:** {st.session_state.sidebar_summary['reward']:.2f}  \n"
                f"**Threat:** {st.session_state.sidebar_summary['threat']}"
            )
        except Exception:
            pass

        # Always attempt to build a PNG snapshot to use as a fallback.
        graph_bytes = None
        try:
            graph_bytes = generate_network_graph(
                state["nodes"], env.graph, env.node_types, env.node_count
            )
        except Exception:
            graph_bytes = st.session_state.get("network_graph_fig", None)

        # Ensure persisted positions exist (reset may have cleared them).
        if "topology_positions" not in st.session_state or not st.session_state.get("topology_positions"):
            try:
                st.session_state.topology_positions = nx.spring_layout(G, seed=42, k=2.5)
            except Exception:
                st.session_state.topology_positions = {n: (0.0, 0.0) for n in G.nodes()}

        # If we created a FigureWidget, update its traces in-place.
        if fig_widget is not None:
            try:
                new_fig = build_plotly_topology(state.get("nodes", {}))
                if new_fig is not None:
                    # Update edge coords
                    try:
                        fig_widget.data[0].x = new_fig.data[0].x
                        fig_widget.data[0].y = new_fig.data[0].y
                    except Exception:
                        pass
                    # Update marker positions, sizes, colors and hovertext
                    try:
                        fig_widget.data[1].x = new_fig.data[1].x
                        fig_widget.data[1].y = new_fig.data[1].y
                        # marker properties
                        if hasattr(new_fig.data[1], "marker") and hasattr(fig_widget.data[1], "marker"):
                            try:
                                fig_widget.data[1].marker.color = new_fig.data[1].marker.color
                                fig_widget.data[1].marker.size = new_fig.data[1].marker.size
                                fig_widget.data[1].marker.line = new_fig.data[1].marker.line
                            except Exception:
                                pass
                        fig_widget.data[1].text = new_fig.data[1].text
                        fig_widget.data[1].hovertext = new_fig.data[1].hovertext
                    except Exception:
                        pass
                    # Update labels
                    try:
                        fig_widget.data[2].x = new_fig.data[2].x
                        fig_widget.data[2].y = new_fig.data[2].y
                        fig_widget.data[2].text = new_fig.data[2].text
                    except Exception:
                        pass
                    # Update axis ranges to keep layout stable
                    try:
                        fig_widget.layout.xaxis.range = new_fig.layout.xaxis.range
                        fig_widget.layout.yaxis.range = new_fig.layout.yaxis.range
                    except Exception:
                        pass
                    # Persist latest figure for post-run rendering as JSON
                    try:
                        st.session_state.topology_fig_json = new_fig.to_dict()
                        st.session_state.topology_fig = None
                    except Exception:
                        st.session_state.topology_fig = new_fig
                        st.session_state.topology_fig_json = None
                    # Also persist a snapshot of node states to rebuild later
                    try:
                        st.session_state.topology_nodes_snapshot = deepcopy(state.get("nodes", {}))
                    except Exception:
                        st.session_state.topology_nodes_snapshot = state.get("nodes", {})
            except Exception:
                # If updating the widget fails, fall back to PNG rendering only.
                if graph_bytes and graph_slot is not None:
                    st.session_state.network_graph_fig = graph_bytes
                    _render_graph_image(graph_slot, graph_bytes)
                # disable further widget updates
                fig_widget = None
        if fig_widget is None and graph_bytes and graph_slot is not None:
            st.session_state.network_graph_fig = graph_bytes
            _render_graph_image(graph_slot, graph_bytes)

        if chart_slot is not None:
            # If we created a FigureWidget for the SOC trend, update it in-place.
            if 'soc_fig_widget' in locals() and soc_fig_widget is not None:
                try:
                    new_soc_fig = build_soc_trend_figure(metrics)
                except Exception:
                    new_soc_fig = None

                if new_soc_fig is not None:
                    try:
                        # If traces count matches, update arrays in-place.
                        if len(soc_fig_widget.data) == len(new_soc_fig.data):
                            for i in range(len(new_soc_fig.data)):
                                try:
                                    soc_fig_widget.data[i].x = new_soc_fig.data[i].x
                                    soc_fig_widget.data[i].y = new_soc_fig.data[i].y
                                except Exception:
                                    pass
                        else:
                            # Replace traces if the structure changed.
                            try:
                                soc_fig_widget.data = new_soc_fig.data
                            except Exception:
                                # Fallback: rebuild widget (one-time replacement)
                                try:
                                    new_widget = go.FigureWidget(new_soc_fig)
                                    chart_slot.plotly_chart(new_widget, use_container_width=True, config={"responsive": True}, key="overview_soc_trend_rebuild")
                                    soc_fig_widget = new_widget
                                except Exception:
                                    pass
                        try:
                            st.session_state.soc_trend_fig_json = new_soc_fig.to_dict()
                            st.session_state.soc_trend_fig = None
                        except Exception:
                            st.session_state.soc_trend_fig = new_soc_fig
                            st.session_state.soc_trend_fig_json = None
                    except Exception:
                        pass
            else:
                try:
                    live_soc_fig = build_soc_trend_figure(metrics)
                except Exception:
                    live_soc_fig = None

                if live_soc_fig is not None:
                    try:
                        chart_slot.plotly_chart(
                            live_soc_fig,
                            use_container_width=True,
                            config={"responsive": True},
                            key=f"overview_soc_trend_live_{step}"
                        )
                        try:
                            st.session_state.soc_trend_fig_json = live_soc_fig.to_dict()
                            st.session_state.soc_trend_fig = None
                        except Exception:
                            st.session_state.soc_trend_fig = live_soc_fig
                            st.session_state.soc_trend_fig_json = None
                    except Exception:
                        pass

        step_hist   = metrics.get("step_history", [])
        threat_hist = metrics.get("threat_history", [])
        comp_hist   = metrics.get("compromise_history", [])
        def_hist    = metrics.get("defense_history", [])
        mom_hist    = metrics.get("momentum_history", [])

        if feed_slot is not None:
            _render_event_console(metrics.get("event_logs", []), placeholder=feed_slot)

            # Update compact timeline preview in-place to reflect recent events
            if timeline_container is not None:
                try:
                    # Clear previous content and render a compact tail preview
                    try:
                        pass
                    except Exception:
                        pass

                    if st.session_state.get("attack_df") is not None:
                        preview_df = st.session_state.attack_df
                    else:
                        preview_df = build_timeline_df(state.get("events", []))

                    display_columns = [
                        "Event ID", "Time", "Stage", "Severity", "Technique", "Target Node",
                        "Source Node", "CVE", "Actor", "Confidence", "Status"
                    ]

                    if preview_df is not None and not preview_df.empty:
                        display_df = preview_df[display_columns].reset_index(drop=True)
                        preview_df_tail = display_df.tail(10)
                        with timeline_container.container():
                            st.markdown("### Attack Timeline Log")
                            st.markdown('<div class="soc-card soc-table-card">', unsafe_allow_html=True)
                            st.dataframe(preview_df_tail, use_container_width=False, width=1200, height=220, hide_index=True)
                            st.markdown('</div>', unsafe_allow_html=True)
                    else:
                        with timeline_container.container():
                            st.markdown("### Attack Timeline Log")
                            st.markdown('<div class="empty-placeholder">&#9654; Attack timeline will appear here once events are generated.</div>', unsafe_allow_html=True)
                except Exception:
                    # Non-fatal: continue simulation even if timeline preview update fails
                    pass

        time.sleep(speed)

        if env.max_steps and (step + 1) >= env.max_steps:
            break

    state["simulation"]["status"]    = "completed"
    state["simulation"]["running"]   = False
    state["simulation"]["completed"] = True
    # Recompute final metrics and ensure session_state is fully finalized
    aggregate_state_metrics(state)

    # Persist final SOC metrics snapshot so Overview renders reliably after completion
    try:
        st.session_state.soc_metrics = metrics.copy()
    except Exception:
        st.session_state.soc_metrics = st.session_state.get("soc_metrics", {})

    # Generate final analytic artifacts and persist them to session_state
    try:
        attack_df = build_timeline_df(state.get("events", []))
    except Exception:
        attack_df = None
    try:
        mitre_df = build_mitre_table(metrics.get("technique_counts", {}))
    except Exception:
        mitre_df = None
    try:
        ioc_df = IOCEngine.generate_registry_df(state.get("events", []))
    except Exception:
        ioc_df = None

    # Live feed entries
    live_feed = metrics.get("event_logs", [])

    # Persist datasets so post-simulation renders read from session_state only
    st.session_state.attack_df = attack_df
    st.session_state.mitre_df = mitre_df
    st.session_state.ioc_df = ioc_df
    st.session_state.live_feed = live_feed

    # Mark simulation completion only after artifacts are stored
    # Mark simulation completion and indicate simulation is no longer running
    st.session_state.simulation_complete = True
    st.session_state.simulation_started = False

    # Build and persist final figures so Overview can render them after the run
    try:
        final_nodes = state.get("nodes", {})
        st.session_state.topology_fig = None
        st.session_state.topology_fig_json = None
        # Persist node snapshot as a final fallback for re-rendering
        try:
            st.session_state.topology_nodes_snapshot = deepcopy(final_nodes)
        except Exception:
            st.session_state.topology_nodes_snapshot = final_nodes
    except Exception:
        pass

    try:
        final_soc_fig = build_soc_trend_figure(st.session_state.get("soc_metrics", metrics))
        if final_soc_fig is not None:
            try:
                st.session_state.soc_trend_fig_json = final_soc_fig.to_dict()
                st.session_state.soc_trend_fig = None
            except Exception:
                st.session_state.soc_trend_fig = final_soc_fig
                st.session_state.soc_trend_fig_json = None
    except Exception:
        pass

    try:
        final_graph_bytes = generate_network_graph(
            state.get("nodes", {}), env.graph, env.node_types, env.node_count
        )
        if final_graph_bytes:
            st.session_state.network_graph_fig = final_graph_bytes
    except Exception:
        pass

    # Force full UI refresh so Overview re-renders from persisted session_state
    try:
        if hasattr(st, "rerun"):
            st.rerun()
        else:
            st.experimental_rerun()
    except Exception:
        try:
            st.experimental_rerun()
        except Exception:
            pass
