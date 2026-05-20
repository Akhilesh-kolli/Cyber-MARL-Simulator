# SOC Dashboard v2.0 — Hardened Architecture (Phase 5.5)
# All metric logic delegated to: backend/, analytics/, visualization/, components/

import sys
import time
import json
import numpy as np
import networkx as nx
import streamlit as st
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

# ── Component imports ────────────────────────────────────────────────────────
from components.kpi_cards import render_kpi_cards
from components.threat_panels import render_threat_hunt_panel, render_ioc_panel
from components.mitre_panels import render_mitre_panel
from components.executive_panels import render_executive_panel
from visualization.timeline_renderer import render_timeline_section

# ── Session state initialization (canonical, single source of truth) ─────────
initialize_session_state(st)

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
pos = nx.spring_layout(G, seed=42, k=1.3)

# ── Aliases for clean access ─────────────────────────────────────────────────
state      = st.session_state.simulation_state
metrics    = state["metrics"]
sim_status = state["simulation"]

# ── Header row ───────────────────────────────────────────────────────────────
top1, top2 = st.columns([3, 2])

defense_eff = metrics.get("defense_effectiveness", 0.0)
attack_stage = metrics.get("attack_stage", "Idle")

with top1:
    if st.session_state.simulation_complete:
        monitor_status = "🟢 SIMULATION COMPLETED — SOC ANALYTICS READY"
    elif st.session_state.simulation_started:
        monitor_status = "🔴 LIVE THREAT MONITORING ACTIVE"
    else:
        monitor_status = "⚪ STANDBY MODE — Awaiting Simulation"
    st.markdown(f"### 🛡️ CYBER MARL SOC PLATFORM\n##### {monitor_status}")

with top2:
    pill1, pill2, pill3 = st.columns(3)
    with pill1:
        if not st.session_state.simulation_started:
            st.info("👾 ATTACKER: IDLE")
        elif not st.session_state.simulation_complete:
            stage_upper = attack_stage.upper()
            if attack_stage in ["Reconnaissance", "Discovery", "Scanning", "Idle"]:
                st.warning(f"👾 ATTACKER: {stage_upper}")
            else:
                st.error(f"👾 ATTACKER: {stage_upper}")
        else:
            st.info(f"👾 ATTACKER: FINISHED ({attack_stage.upper()})")
    with pill2:
        if not st.session_state.simulation_started:
            st.info("🛡️ DEFENDER: STANDBY")
        elif not st.session_state.simulation_complete:
            if defense_eff >= 70.0:
                st.success(f"🛡️ DEFENDER: ACTIVE ({defense_eff:.1f}%)")
            elif defense_eff >= 40.0:
                st.warning(f"🛡️ DEFENDER: ACTIVE ({defense_eff:.1f}%)")
            else:
                st.error(f"🛡️ DEFENDER: ALERT ({defense_eff:.1f}%)")
        else:
            if defense_eff >= 60.0:
                st.success(f"🛡️ DEFENDER: SECURED ({defense_eff:.1f}%)")
            else:
                st.error(f"🛡️ DEFENDER: COMPROMISED ({defense_eff:.1f}%)")
    with pill3:
        if not st.session_state.simulation_started:
            st.warning("⚙️ ENGINE: READY")
        elif not st.session_state.simulation_complete:
            st.success("⚙️ ENGINE: SIMULATING")
        else:
            st.success("⚙️ ENGINE: ANALYZED")

# ── Top-level header KPIs ────────────────────────────────────────────────────
kpi1, kpi2, kpi3, kpi4 = st.columns(4)

if not st.session_state.simulation_started:
    kpi1.metric("Active Threats",    "0",       delta="Idle Monitoring")
    kpi2.metric("Compromised Nodes", "0",       delta="No Compromise")
    kpi3.metric("Defense Success",   "Standby", delta="Awaiting Simulation")
    kpi4.metric("Incident Status",   "NORMAL",  delta="System Idle")
else:
    comp_assets = metrics.get("compromised_assets", set())
    risk_s      = metrics.get("risk_score", 0.0)
    def_eff_str = f"{defense_eff:.1f}%"
    if risk_s >= 80 or len(comp_assets) >= 5:
        inc_status = "ACTIVE INCIDENT" if risk_s >= 80 else "BREACH CONFIRMED"
        inc_delta  = "SOC Escalated" if risk_s >= 80 else "Critical Response"
    else:
        inc_status = "MONITORING"
        inc_delta  = "SOC Tracking"
    kpi1.metric("Active Threats",    str(len(metrics.get("threat_history", []))), delta="Threat Activity")
    kpi2.metric("Compromised Nodes", str(len(metrics.get("compromise_history", []))), delta="Hosts Impacted")
    kpi3.metric("Defense Success",   def_eff_str, delta="Active Defense")
    kpi4.metric("Incident Status",   inc_status,  delta=inc_delta)

# ── Sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Simulation Controls")

speed = st.sidebar.slider("Animation Speed", min_value=0.1, max_value=2.0, value=0.5, step=0.1)

run_button   = st.sidebar.button("▶ Start Simulation")
reset_button = st.sidebar.button("🔄 Reset Simulation")

if reset_button:
    reset_entire_simulation(st)
    st.session_state.soc_workspace = "Overview"
    st.rerun()


if "soc_workspace" not in st.session_state:
    st.session_state.soc_workspace = "Overview"

if run_button:
    st.session_state.soc_workspace = "Overview"

workspace = st.sidebar.radio(
    "SOC Workspace",
    ["Overview", "Threat Hunt", "IOC Intelligence", "MITRE Analytics", "Executive View"],
    key="soc_workspace"
)

timer_placeholder = st.sidebar.empty()

# ── Real Infrastructure Status (Overview only) ───────────────────────────────
if workspace == "Overview":
    services = scan_local_services()
    st.markdown("## 🌐 Real Infrastructure Status")
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

# ── Persistent graph + event console placeholders ────────────────────────────
graph_placeholder = st.empty()
log_placeholder   = st.empty()

if workspace == "Overview":
    # Render cached graph
    if st.session_state.network_graph_fig is not None:
        with graph_placeholder.container():
            st.markdown('<div class="graph-card">', unsafe_allow_html=True)
            st.image(st.session_state.network_graph_fig, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

    # Live event console
    st.markdown("## 📜 Live Threat Events")
    event_feed_items = []
    if not st.session_state.simulation_started:
        event_feed_items.append('<div class="event-item info-event">[INFO] SOC monitoring initialized successfully</div>')
        event_feed_items.append('<div class="event-item standby-event">[STANDBY] Awaiting attacker simulation trigger</div>')
    else:
        logs = metrics.get("event_logs", [])
        if not logs:
            event_feed_items.append('<div class="event-item info-event">[INFO] Simulation started...</div>')
        else:
            for log in logs[:15]:
                cls = "standby-event"
                if any(kw in log for kw in ["ALERT", "CRITICAL", "Compromise", "Breach"]):
                    cls = "critical-event"
                elif any(kw in log for kw in ["WARNING", "Recon", "Scan"]):
                    cls = "warning-event"
                elif any(kw in log for kw in ["INFO", "Defender"]):
                    cls = "info-event"
                event_feed_items.append(f'<div class="event-item {cls}">{log}</div>')

    st.markdown(
        f'<div class="event-console">{"".join(event_feed_items)}</div>',
        unsafe_allow_html=True
    )

    # Final log after simulation
    if st.session_state.simulation_complete and metrics.get("event_logs"):
        log_placeholder.text_area(
            "Final Threat Feed Logs",
            "\n".join(metrics["event_logs"][-20:]),
            height=260,
            disabled=True,
            key="soc_final_feed"
        )

# ── Alert fatigue guard ────────────────────────────────────────────────────────
if "alert_fatigue_score" not in st.session_state:
    st.session_state.alert_fatigue_score = 0

# ── Pre-simulation workspace renders (read-only) ──────────────────────────────
if workspace == "Threat Hunt":
    render_threat_hunt_panel(state)

elif workspace == "IOC Intelligence":
    render_ioc_panel(state)

# ── Simulation run loop ────────────────────────────────────────────────────────
if run_button:
    st.session_state.simulation_started = True
    st.session_state.simulation_complete = False

    # Reset canonical state for a fresh run
    reset_entire_simulation(st)
    st.session_state.simulation_started = True

    # Re-alias after reset
    state   = st.session_state.simulation_state
    metrics = state["metrics"]
    state["simulation"]["status"]  = "running"
    state["simulation"]["running"] = True

    # Reset env observation
    obs, _ = env.reset()

    chart_placeholder    = st.empty()
    timeline_placeholder = st.empty()

    for step in range(env.max_steps):
        # ── Execute one canonical simulation step ────────────────────────────
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

        # ── Aggregate all derived metrics + executive narratives ─────────────
        aggregate_state_metrics(state)

        # ── Live header KPI refresh ─────────────────────────────────────────
        comp_c   = metrics.get("compromised_count", 0)
        risk_s   = metrics.get("risk_score", 0.0)
        rew_val  = metrics.get("total_reward", 0.0)
        thr_lvl  = metrics.get("threat_level", "LOW")

        reward_metric = col1.empty() if "col1" in dir() else st.empty()

        timer_placeholder.markdown(
            f"**Step:** {step + 1} / {env.max_steps}  \n"
            f"**Risk:** {risk_s:.1f}%  \n"
            f"**Reward:** {rew_val:.2f}  \n"
            f"**Threat:** {thr_lvl}"
        )

        # ── Network graph update ─────────────────────────────────────────────
        if workspace == "Overview":
            graph_bytes = generate_network_graph(
                state["nodes"], env.graph, env.node_types, env.node_count
            )
            if graph_bytes:
                st.session_state.network_graph_fig = graph_bytes
                with graph_placeholder.container():
                    st.markdown('<div class="graph-card">', unsafe_allow_html=True)
                    st.image(graph_bytes, use_container_width=True)
                    st.markdown('</div>', unsafe_allow_html=True)

        # ── Live trend chart ─────────────────────────────────────────────────
        if workspace == "Overview":
            step_hist    = metrics.get("step_history", [])
            threat_hist  = metrics.get("threat_history", [])
            comp_hist    = metrics.get("compromise_history", [])
            def_hist     = metrics.get("defense_history", [])
            mom_hist     = metrics.get("momentum_history", [])

            n = min(len(step_hist), len(threat_hist), len(comp_hist))
            if n >= 2:
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
                if value_vars:
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
                        paper_bgcolor="#071028", plot_bgcolor="#071028",
                        font_color="white",
                        xaxis=dict(showgrid=True, gridcolor="#1e293b"),
                        yaxis=dict(showgrid=True, gridcolor="#1e293b"),
                        margin=dict(l=20, r=20, t=50, b=20), height=400
                    )
                    with chart_placeholder.container():
                        st.plotly_chart(fig_chart, use_container_width=True,
                                        config={"responsive": True})

        # ── Live event console update ────────────────────────────────────────
        if workspace == "Overview":
            logs = metrics.get("event_logs", [])
            feed_items = []
            for log in logs[:15]:
                cls = "standby-event"
                if any(kw in log for kw in ["ALERT", "CRITICAL", "Compromise", "Breach"]):
                    cls = "critical-event"
                elif any(kw in log for kw in ["WARNING", "Recon", "Scan"]):
                    cls = "warning-event"
                elif any(kw in log for kw in ["INFO", "Defender"]):
                    cls = "info-event"
                feed_items.append(f'<div class="event-item {cls}">{log}</div>')
            log_placeholder.markdown(
                f'<div class="event-console">{"".join(feed_items)}</div>',
                unsafe_allow_html=True
            )

        # Animation pacing
        time.sleep(speed)

        if env.max_steps and (step + 1) >= env.max_steps:
            break

    # ── Simulation complete ──────────────────────────────────────────────────
    state["simulation"]["status"]    = "completed"
    state["simulation"]["running"]   = False
    state["simulation"]["completed"] = True
    st.session_state.simulation_complete = True

    # Final aggregate pass
    aggregate_state_metrics(state)

    st.success("✅ Simulation Complete — SOC Analytics Generated")

# ── Post-simulation workspace renders ────────────────────────────────────────

# Re-alias in case reset was called
state   = st.session_state.simulation_state
metrics = state["metrics"]

if workspace == "Overview" and st.session_state.simulation_started:
    render_kpi_cards(
        critical_alerts    = metrics.get("critical_alerts", 0),
        sqli_detected      = metrics.get("sqli_detected", 0),
        recon_events       = metrics.get("recon_events", 0),
        discovery_events   = metrics.get("discovery_events", 0),
        risk_score         = metrics.get("risk_score", 0.0),
        incident_priority  = metrics.get("incident_priority", "LOW"),
        incident_status    = metrics.get("incident_status", "IDLE"),
        attack_success_rate  = metrics.get("attack_success_rate", 0.0),
        defense_effectiveness = metrics.get("defense_effectiveness", 0.0),
        attacker_profile   = metrics.get("attacker_profile", "Unknown"),
        estimated_dwell_time = metrics.get("estimated_dwell_time", 0),
        high_severity_events = metrics.get("high_severity_events", 0)
    )
elif workspace == "Overview" and not st.session_state.simulation_started:
    st.info("▶ Run the simulation to populate SOC metrics.")

if workspace == "Overview":
    render_timeline_section(state)

elif workspace == "Threat Hunt":
    if st.session_state.simulation_started:
        render_threat_hunt_panel(state)

elif workspace == "IOC Intelligence":
    if st.session_state.simulation_started:
        render_ioc_panel(state)

elif workspace == "MITRE Analytics":
    render_mitre_panel(state)

elif workspace == "Executive View":
    render_executive_panel(state)
