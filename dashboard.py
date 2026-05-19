import plotly.express as px
import pandas as pd
import streamlit as st
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
import time
from pathlib import Path
import sys
from datetime import datetime
from src.marlon.real_scan import scan_local_services
from src.marlon.attack_engine import (
    probe_http_service,
    probe_tcp_service
)
from src.marlon.dvwa_tester import (
    login_dvwa,
    test_basic_sqli
)
from src.marlon.mitre_mapper import (
    map_attack_to_mitre
)
from src.marlon.threat_analyzer import (
    calculate_threat_level
)
from src.marlon.kill_chain import (
    map_kill_chain
)
from event_engine import (
    build_event,
    format_event_log,
    SIMULATION_NODES,
    NODE_TO_SERVICE,
    REAL_SERVICES,
    VULNERABILITY_DB,
    DETECTION_RULES
)
from risk_engine import (
    get_incident_priority,
    get_incident_status,
    get_attacker_profile,
    get_soc_recommendation,
    get_dwell_time,
    get_alert_fatigue_score,
    get_attack_success_rate,
    get_dominant_technique,
)
from soc_engine import SOCEngine
from ioc_engine import IOCEngine
from analytics import (
    build_timeline_df,
    build_chart_df,
    build_mitre_pie,
    build_mitre_table,
    build_escalation_chart,
    filter_timeline,
    export_soc_report,
)
from components.kpi_cards import render_kpi_cards

# --------------------------------------------------
# PAGE CONFIG — must be first Streamlit command
# --------------------------------------------------
st.set_page_config(
    page_title="Cyber MARL Threat Simulation Platform",
    page_icon="🛡️",
    layout="wide"
)

def load_css():

    with open("styles/theme.css") as f:

        st.markdown(
            f"<style>{f.read()}</style>",
            unsafe_allow_html=True
        )

load_css()
top1, top2 = st.columns([3, 2])
if "simulation_started" not in st.session_state:
    st.session_state.simulation_started = False

if "simulation_data" not in st.session_state:
    st.session_state.simulation_data = {}

SIM_STATE = st.session_state.simulation_data
with top1:

    monitor_status = (
        "🟢 LIVE MONITORING ACTIVE"
        if st.session_state.simulation_started
        else "⚪ STANDBY MODE"
    )

    st.markdown(
        f"""
        ### 🛡️ CYBER MARL SOC PLATFORM
        ##### {monitor_status}
        """
    )
with top2:

    pill1, pill2, pill3 = st.columns(3)

    with pill1:
        st.success("ATTACKER")

    with pill2:
        st.info("DEFENDER")

    with pill3:
        st.warning("ENGINE")

kpi1, kpi2, kpi3, kpi4 = st.columns(4)

# PRE-SIMULATION STATE
if not st.session_state.simulation_started:

    active_threats = "0"
    threat_delta = "Idle Monitoring"

    compromised_nodes = "0"
    compromised_delta = "No Compromise"

    defense_success = "Standby"
    defense_delta = "Awaiting Simulation"

    incident_status = "NORMAL"
    incident_delta = "System Idle"

# POST-SIMULATION STATE
else:

    active_threats = str(len(SIM_STATE["threat_history"]))
    threat_delta = "Threat Activity"

    compromised_nodes = str(len(SIM_STATE["compromise_history"]))
    compromised_delta = "Hosts Impacted"

    defense_success = f"{defense_effectiveness:.1f}%"
    defense_delta = "Active Defense"

    if risk_score >= 80:
        incident_status = "ACTIVE INCIDENT"
        incident_delta = "SOC Escalated"

    elif compromised_count >= 5:
        incident_status = "BREACH CONFIRMED"
        incident_delta = "Critical Response"

    else:
        incident_status = "MONITORING"
        incident_delta = "SOC Tracking"

with kpi1:
    st.metric(
        "Active Threats",
        active_threats,
        delta=threat_delta
    )

with kpi2:
    st.metric(
        "Compromised Nodes",
        compromised_nodes,
        delta=compromised_delta
    )

with kpi3:
    st.metric(
        "Defense Success",
        defense_success,
        delta=defense_delta
    )

with kpi4:
    st.metric(
        "Incident Status",
        incident_status,
        delta=incident_delta
    )

if not st.session_state.simulation_started:

    st.markdown("""
    <div class="status-banner standby-banner">
        ⚪ SYSTEM READY — Awaiting Simulation Execution
    </div>
    """, unsafe_allow_html=True)

else:

    st.markdown(f"""
    <div class="status-banner active-banner">
        🔴 ACTIVE THREAT DETECTION — Attack Simulation Running
    </div>
    """, unsafe_allow_html=True)


VULNERABILITY_DB = {
    "DVWA": {
        "cve": "CVE-2023-9999",
        "name": "SQL Injection",
        "cvss": 9.8,
        "mitre": "T1190",
        "severity": "CRITICAL"
    },
    "MySQL": {
        "cve": "CVE-2016-6662",
        "name": "MySQL Remote Root Code Execution",
        "cvss": 8.5,
        "mitre": "T1021",
        "severity": "HIGH"
    },
    "Nginx": {
        "cve": "CVE-2021-23017",
        "name": "Nginx Resolver RCE",
        "cvss": 7.7,
        "mitre": "T1190",
        "severity": "HIGH"
    }
}

DETECTION_RULES = {
    "SQL Injection": {
        "signature": "ET WEB_SERVER SQL Injection Attempt",
        "severity": "HIGH",
        "confidence": 92
    },
    "Active Scanning": {
        "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "severity": "MEDIUM",
        "confidence": 81
    },
    "Remote Services": {
        "signature": "SIGMA Lateral Movement Remote Service Execution",
        "severity": "HIGH",
        "confidence": 88
    },
    "Network Service Discovery": {
        "signature": "ET POLICY Internal Network Scan",
        "severity": "LOW",
        "confidence": 73
    }
}

ATTACK_SEVERITY = {
    "T1190": "CRITICAL",
    "T1021": "HIGH",
    "T1046": "MEDIUM",
    "T1595": "LOW"
}

NODE_MAPPING = {
    0: "DVWA",
    1: "MySQL",
    2: "Nginx"
}

ASSET_CRITICALITY = {
    "DVWA": 4,
    "MySQL": 5,
    "Nginx": 3
}

# --------------------------------------------------
# AI DECISION EXPLANATION
# --------------------------------------------------

def explain_action(action, compromised_count, attack_result=None):

    if action < env.node_count:

        if action == 1:
            if attack_result and attack_result.get("vulnerability"):
                return (
                    "Attacker selected DVWA because "
                    "a vulnerable HTTP endpoint was "
                    "detected with possible SQL injection."
                )
            return (
                "Attacker targeted DVWA because "
                "web applications provide high "
                "initial-access value."
            )

        elif action == 2:
            return (
                "Attacker targeted MySQL because "
                "database services may expose "
                "credential or lateral movement opportunities."
            )

        return (
            "Attacker selected this node based on "
            "reinforcement-learning reward optimization "
            "and compromise probability."
        )

    else:
        if compromised_count >= 3:
            return (
                "Defender initiated containment because "
                "multiple nodes are compromised."
            )
        return (
            "Defender attempted proactive risk reduction "
            "and network stabilization."
        )

# --------------------------------------------------
# IMPORT PROJECT MODULES
# --------------------------------------------------
sys.path.append(str(Path(__file__).resolve().parent / "src"))

from stable_baselines3 import PPO
from marlon.graph_env import GraphCyberEnv



# --------------------------------------------------
# LOAD MODELS
# --------------------------------------------------
@st.cache_resource
def load_models():
    attacker = PPO.load("models/ppo_attacker_graph")
    defender = PPO.load("models/ppo_defender_graph")
    return attacker, defender

attacker, defender = load_models()

# --------------------------------------------------
# DVWA SESSION INITIALIZATION
# --------------------------------------------------
dvwa_logged_in = login_dvwa()

# --------------------------------------------------
# ENVIRONMENT
# --------------------------------------------------
env = GraphCyberEnv()
real_ports = {
    0: 5000,   # Nginx
    1: 8080,   # DVWA
    2: 3306    # MySQL
}
obs = env.reset()

# --------------------------------------------------
# BUILD GRAPH
# --------------------------------------------------
G = nx.Graph()

for i in range(env.node_count):
    G.add_node(i)

for i in range(env.node_count):
    for j in range(i + 1, env.node_count):
        if env.graph[i, j] == 1:
            G.add_edge(i, j)

# --------------------------------------------------
# LABELS
# --------------------------------------------------
labels = {}

for i in range(env.node_count):
    node_name = env.node_types[i]
    if node_name == "DomainController":
        node_name = "Domain\nController"
    labels[i] = f"{i}\n{node_name}"

# --------------------------------------------------
# FIXED GRAPH LAYOUT
# --------------------------------------------------
pos = nx.spring_layout(G, seed=42, k=1.3)

# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------
st.sidebar.title("⚙️ Simulation Controls")

speed = st.sidebar.slider(
    "Animation Speed",
    min_value=0.1,
    max_value=2.0,
    value=0.5,
    step=0.1
)

run_button = st.sidebar.button("▶ Start Simulation")

if "simulation_started" not in st.session_state:
    st.session_state.simulation_started = False

if "simulation_complete" not in st.session_state:
    st.session_state.simulation_complete = False

if "simulation_data" not in st.session_state:
    st.session_state.simulation_data = {

        # CORE
        "risk_score": 0,
        "incident_priority": "LOW",
        "incident_status": "IDLE",
        "threat_level": "LOW",

        # IOC
        "ioc_ports": set(),
        "ioc_techniques": set(),
        "compromised_assets": set(),
        "observed_attack_stages": set(),

        # COUNTERS
        "critical_alerts": 0,
        "high_severity_events": 0,
        "recon_events": 0,
        "discovery_events": 0,
        "lateral_movement_count": 0,

        # PERFORMANCE
        "attack_attempts": 0,
        "successful_attacks": 0,
        "successful_defenses": 0,
        "failed_defenses": 0,
        "defense_actions_count": 0,

        # SCORES
        "threat_momentum_score": 0,
        "persistence_score": 0,
        "threat_correlation_score": 0,
        "containment_pressure_score": 0,
        "threat_volatility_score": 0,
        "anomaly_pressure_score": 0,

        # EXECUTIVE
        "soc_recommendation": "Awaiting Simulation",
        "attacker_profile": "Unknown",
        "campaign_type": "Unknown Campaign",

        # TIMELINE
        "timeline_data": [],
        "structured_events": [],
        "event_logs": [],

        # HISTORY
        "step_history": [],
        "threat_history": [],
        "compromise_history": []
    }

workspace = st.sidebar.radio(
    "SOC Workspace",
    [
        "Overview",
        "Threat Hunt",
        "IOC Intelligence",
        "MITRE Analytics",
        "Executive View"
    ]
)

# --------------------------------------------------
# METRICS
# --------------------------------------------------
col1, col2, col3, col4 = st.columns(4)

reward_metric = col1.empty()
comp_metric = col2.empty()
step_metric = col3.empty()
threat_metric = col4.empty()

# --------------------------------------------------
# REAL SERVICE STATUS
# --------------------------------------------------
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

# --------------------------------------------------
# GRAPH PLACEHOLDER
# --------------------------------------------------
graph_placeholder = st.empty()

# --------------------------------------------------
# EVENT LOGS
# --------------------------------------------------
st.markdown("## 📜 Live Threat Events")

if not st.session_state.simulation_started:

    event_feed = """
    <div class="event-console">

    <div class="event-item info-event">
    [INFO] SOC monitoring initialized successfully
    </div>

    <div class="event-item standby-event">
    [STANDBY] Awaiting attacker simulation trigger
    </div>

    </div>
    """

else:

    event_feed = """
    <div class="event-console">

    <div class="event-item critical-event">
    [ALERT] Active adversarial activity detected
    </div>

    <div class="event-item warning-event">
    [WARNING] Multi-agent attack simulation in progress
    </div>

    <div class="event-item info-event">
    [INFO] Defender agent responding to threat events
    </div>

    </div>
    """

st.markdown(event_feed, unsafe_allow_html=True)

log_placeholder = st.empty()

# --------------------------------------------------
# IOC INITIALIZATION — values live in SIM_STATE
# (initialized in session_state block above)
# --------------------------------------------------

# --------------------------------------------------
# alert_fatigue_score session guard — must exist
# before Threat Hunt renders
# --------------------------------------------------
if "alert_fatigue_score" not in st.session_state:
    st.session_state.alert_fatigue_score = 0

# --------------------------------------------------
# Threat Hunt Summary
# --------------------------------------------------
st.markdown("## 🕵️ Threat Hunt Summary")
hunt1, hunt2, hunt3 = st.columns(3)

hunt1_placeholder = hunt1.empty()
hunt2_placeholder = hunt2.empty()
hunt3_placeholder = hunt3.empty()


if st.session_state.simulation_started:
    hunt1_placeholder.metric(
        "Unique Techniques",
        len(SIM_STATE["ioc_techniques"])
    )

    hunt2_placeholder.metric(
        "Observed Ports",
        len(SIM_STATE["ioc_ports"])
    )

    hunt3_placeholder.metric(
        "Compromised Assets",
        len(SIM_STATE["compromised_assets"])
    )

    st.markdown("## 🛡️ Detection Engineering")

    detect1, detect2 = st.columns(2)

    detect1.metric(
        "Alert Fatigue Score",
        f"{st.session_state.alert_fatigue_score:.1f}"
    )

    detect2.metric(
        "SOC Recommendation",
        SIM_STATE["soc_recommendation"]
    )

else:
    st.info(
        "▶ Run the simulation to activate threat hunting analytics."
    )

st.markdown("## 🧠 IOC Intelligence")

ioc1, ioc2 = st.columns(2)

ioc_ports_placeholder = ioc1.empty()
ioc_tech_placeholder  = ioc2.empty()

if SIM_STATE["ioc_ports"]:
    ioc_ports_placeholder.code(
        ", ".join(sorted(SIM_STATE["ioc_ports"])),
        language="text"
    )
else:
    ioc_ports_placeholder.code(
        "No ports observed yet.",
        language="text"
    )

if SIM_STATE["ioc_techniques"]:
    ioc_tech_placeholder.code(
        ", ".join(sorted(SIM_STATE["ioc_techniques"])),
        language="text"
    )
else:
    ioc_tech_placeholder.code(
        "No techniques observed yet.",
        language="text"
    )

# --------------------------------------------------
# LOCAL SESSION VARIABLES
# (not stored in SIM_STATE — per-run locals only)
# --------------------------------------------------
soc_engine = SOCEngine()
ioc_engine = IOCEngine()

compromised_count       = 0
estimated_dwell_time    = 0
technique_id            = "N/A"
attack_stage            = "Idle"
sqli_detected           = 0
alert_fatigue_score     = 0
soc_stability_index     = 100
research_consistency_score = 100
alert_confidence_total  = 0
alert_count             = 0
attack_success_rate     = 0
defense_effectiveness   = 0

# technique_counts: local per-run counter (not in SIM_STATE)
technique_counts = {
    "T1190": 0,
    "T1021": 0,
    "T1046": 0,
    "T1595": 0
}

# --------------------------------------------------
# RUN SIMULATION
# --------------------------------------------------
if run_button:

    st.session_state.simulation_started = True
    st.session_state.simulation_complete = False

    SIM_STATE.update({
        "ioc_ports": set(),
        "ioc_techniques": set(),
        "compromised_assets": set(),
        "observed_attack_stages": set(),

        "timeline_data": [],
        "structured_events": [],
        "event_logs": [],

        "step_history": [],
        "threat_history": [],
        "compromise_history": [],

        "critical_alerts": 0,
        "high_severity_events": 0,
        "recon_events": 0,
        "discovery_events": 0,
        "lateral_movement_count": 0,

        "attack_attempts": 0,
        "successful_attacks": 0,
        "successful_defenses": 0,
        "failed_defenses": 0,
        "defense_actions_count": 0,

        "threat_momentum_score": 0,
        "persistence_score": 0,
        "threat_correlation_score": 0,
        "containment_pressure_score": 0,
        "threat_volatility_score": 0,
        "anomaly_pressure_score": 0,

        "risk_score": 0,
        "incident_priority": "LOW",
        "incident_status": "IDLE",
        "threat_level": "LOW",

        "soc_recommendation": "Awaiting Simulation",
        "attacker_profile": "Unknown",
        "campaign_type": "Unknown Campaign"
    })

    chart_placeholder    = st.empty()
    timeline_placeholder = st.empty()

    total_reward      = 0
    compromised_count = 0
    sqli_detected     = 0
    alert_confidence_total = 0
    alert_count = 0

    # ------------------------------------------
    # ADJACENCY-AWARE LATERAL MOVEMENT
    # ------------------------------------------
    def get_reachable_nodes(obs_state):

        compromised_nodes = [
            i for i in range(env.node_count)
            if obs_state[i] == 1
        ]

        reachable = set()

        for node in compromised_nodes:

            neighbors = list(G.neighbors(node))

            for neighbor in neighbors:

                if obs_state[neighbor] == 0:
                    reachable.add(neighbor)

        return list(reachable)

    for step in range(env.max_steps):

        # ------------------------------------------
        # ATTACKER ACTION
        # ------------------------------------------
        action, _ = attacker.predict(obs, deterministic=False)
        reachable_nodes = get_reachable_nodes(obs)

        if len(reachable_nodes) > 0:
            predicted_node = int(action)

            if predicted_node not in reachable_nodes:
                action = np.random.choice(reachable_nodes)

        previous_compromised = int(np.sum(obs))
        obs, reward, done, _ = env.step(action)
        current_compromised  = int(np.sum(obs))
        compromised_count    = current_compromised

        # ------------------------------------------
        # DEFENDER ACTION
        # ------------------------------------------
        if not done:
            def_action, _ = defender.predict(
                obs,
                deterministic=False
            )
            # Defender operates on current state directly.
            # No second env.step() — that would advance the
            # environment twice per step, causing reward collapse.


        # ------------------------------------------
        # METRICS
        # ------------------------------------------

        risk_score_live = (
            (compromised_count * 25)
            + (SIM_STATE["critical_alerts"] * 8)
            + (SIM_STATE["high_severity_events"] * 5)
        )

        if risk_score_live < 80:
            threat_level = "LOW"

        elif risk_score_live < 180:
            threat_level = "MEDIUM"

        elif risk_score_live < 320:
            threat_level = "HIGH"

        else:
            threat_level = "CRITICAL"

        if SIM_STATE["attack_attempts"] > 0:
            attack_success_rate = (SIM_STATE["successful_attacks"] / SIM_STATE["attack_attempts"]) * 100
        else:
            attack_success_rate = 0

        if SIM_STATE["defense_actions_count"] > 0:
            defense_effectiveness = (
                SIM_STATE["successful_defenses"] / SIM_STATE["defense_actions_count"]
            ) * 100
        else:
            defense_effectiveness = 0


        # ------------------------------------------
        # EVENT LOGS
        # ------------------------------------------
        timestamp = datetime.now().strftime("%H:%M:%S")

        # safe defaults — overwritten in attacker branch if applicable
        node_id       = -1
        target_system = "SOC"

        # ==========================================
        # ATTACKER EVENT
        # ==========================================
        attack_result  = None
        detection_info = {}
        vuln_info      = {}

        if action < env.node_count:
            SIM_STATE["attack_attempts"] += 1
            node_id = int(action)

            target_system = NODE_MAPPING.get(node_id, "Unknown")
            asset_weight = ASSET_CRITICALITY.get(target_system, 1)
            vuln_info     = VULNERABILITY_DB.get(target_system, {})
            action_text   = f"Attack Node {node_id}"

            # --------------------------------------
            # REAL SERVICE ATTACKS
            # --------------------------------------
            if node_id in real_ports:
                port = real_ports[node_id]

                if port in [5000, 8080]:
                    attack_result = probe_http_service(port)

                    if port == 8080 and dvwa_logged_in:
                        sqli_result = test_basic_sqli()
                        if sqli_result.get("possible_sqli"):
                            attack_result["vulnerability"] = "SQL Injection Detected"

                elif port == 3306:
                    attack_result = probe_tcp_service(port)

            # --------------------------------------
            # Set technique_id BEFORE any
            # SIM_STATE["ioc_techniques"].add() calls
            # --------------------------------------
            technique_id = vuln_info.get("mitre", "UNKNOWN")

            cvss_score = vuln_info.get("cvss", 5.0)
            attack_momentum = min(
                0.20,
                SIM_STATE["lateral_movement_count"] * 0.015
            )

            exploit_probability = min(
                0.90,
                (cvss_score / 12)
                + (asset_weight * 0.04)
                + attack_momentum
            )

            # --------------------------------------
            # RESULT PARSING
            # --------------------------------------
            if attack_result:

                if current_compromised > previous_compromised:

                    exploit_roll = np.random.random()

                    if exploit_roll <= exploit_probability:
                        SIM_STATE["successful_attacks"] += 1
                        SIM_STATE["compromised_assets"].add(target_system)

                    else:
                        obs[node_id] = 0
                        current_compromised = int(np.sum(obs))

                    if "status_code" in attack_result:
                        action_text += f" | HTTP {attack_result['status_code']}"
                        SIM_STATE["ioc_ports"].add("80")

                        if "vulnerability" in attack_result:
                            action_text += f" | {attack_result['vulnerability']}"

                    elif "port" in attack_result:
                        action_text += f" | Port {attack_result['port']} Open"
                        SIM_STATE["ioc_ports"].add(str(attack_result["port"]))

                else:
                    action_text += " | Service Unreachable"

            # Count technique from VULNERABILITY_DB mapping
            if technique_id in technique_counts:
                technique_counts[technique_id] += 1

            attack_name = ""
            if "SQL Injection"     in action_text:
                attack_name = "SQL Injection"
            elif "Active Scanning" in action_text:
                attack_name = "Active Scanning"
            elif "Remote Services" in action_text:
                attack_name = "Remote Services"
            elif "Service Discovery" in action_text:
                attack_name = "Network Service Discovery"

            if attack_name:
                detection_info = DETECTION_RULES.get(attack_name, {})

        # ==========================================
        # DEFENDER EVENT
        # ==========================================
        else:
            SIM_STATE["defense_actions_count"] += 1
            action_text = "Defender Action"
            technique_id = "N/A"
            kill_chain_stage = "Unknown"

            # Map RL defender output to a node index
            defender_target = int(def_action) % env.node_count

            if compromised_count > 0:
                compromised_nodes = [
                    i for i in range(env.node_count)
                    if obs[i] == 1
                ]

                if compromised_nodes:

                    # --------------------------------------------------
                    # HYBRID RL + RISK DEFENDER TARGETING
                    # RL model guides primary target; risk engine
                    # stabilizes against bad predictions
                    # --------------------------------------------------

                    if defender_target in compromised_nodes:
                        highest_risk_node = defender_target

                    else:
                        priority_targets = []

                        for node in compromised_nodes:
                            node_risk = 0

                            if threat_level == "CRITICAL":
                                node_risk += 5

                            elif threat_level == "HIGH":
                                node_risk += 3

                            if attack_stage == "Persistence":
                                node_risk += 4

                            elif attack_stage == "Lateral Movement":
                                node_risk += 2

                            if NODE_MAPPING.get(node) in SIM_STATE["compromised_assets"]:
                                node_risk += 1

                            priority_targets.append((node, node_risk))

                        highest_risk_node = max(
                            priority_targets,
                            key=lambda x: x[1]
                        )[0]

                    # --------------------------------------------------
                    # ADAPTIVE DEFENSE SUCCESS ENGINE
                    # --------------------------------------------------

                    defense_success_probability = max(
                        0.35,
                        min(
                            0.88,
                            0.72
                            - (compromised_count * 0.04)
                            - (SIM_STATE["threat_momentum_score"] * 0.002)
                            - (SIM_STATE["persistence_score"] * 0.003)
                            + (SIM_STATE["successful_defenses"] * 0.015)
                            + (SIM_STATE["defense_actions_count"] * 0.008)
                        )
                    )
                    defense_roll = np.random.random()

                    if defense_roll <= defense_success_probability:
                        obs[highest_risk_node] = 0

                        contained_asset = NODE_MAPPING.get(highest_risk_node)
                        if contained_asset in SIM_STATE["compromised_assets"]:
                            SIM_STATE["compromised_assets"].remove(contained_asset)

                        SIM_STATE["successful_defenses"] += 1
                        SIM_STATE["event_logs"].insert(
                            0,
                            f"[DEFENDER] Contained Node {highest_risk_node}"
                        )

                        # ------------------------------------------
                        # REWARD: successful containment
                        # ------------------------------------------
                        reward += 6
                        reward += max(0, 12 - compromised_count)
                        reward -= SIM_STATE["persistence_score"] * 0.15

                        SIM_STATE["containment_pressure_score"] += (
                            (len(compromised_nodes) * 2.5)
                            + (SIM_STATE["critical_alerts"] * 0.6)
                            + (SIM_STATE["persistence_score"] * 0.2)
                        )

                        SIM_STATE["containment_pressure_score"] -= (
                            SIM_STATE["successful_defenses"] * 0.15
                        )

                        SIM_STATE["containment_pressure_score"] = max(
                            SIM_STATE["containment_pressure_score"],
                            0
                        )

                        # probabilistic adjacent cleanup
                        for neighbor in range(env.node_count):
                            if env.graph[highest_risk_node][neighbor] == 1:
                                containment_roll = np.random.random()

                                if containment_roll <= 0.45:
                                    obs[neighbor] = 0

                        current_compromised = int(np.sum(obs))
                        compromised_count = current_compromised

                    else:
                        SIM_STATE["failed_defenses"] += 1
                        reward -= 4
                        SIM_STATE["event_logs"].insert(
                            0,
                            "[DEFENDER] Containment Failed"
                        )

                    # --------------------------------------------------
                    # DEFENDER REINFORCEMENT
                    # --------------------------------------------------

                    if SIM_STATE["successful_defenses"] >= 5:
                        defense_success_probability += 0.03

                    if SIM_STATE["critical_alerts"] >= 6:
                        defense_success_probability += 0.04

                    defense_success_probability = min(
                        defense_success_probability,
                        0.92
                    )

        # ------------------------------------------
        # Count techniques from mitre_mapper output
        # this catches T1046 and T1595 which don't
        # appear in VULN_DB
        # ------------------------------------------
        mitre_data = map_attack_to_mitre(action_text)

        if mitre_data:
            action_text += (
                f" | {mitre_data['technique']} "
                f"{mitre_data['name']} "
                f"[{mitre_data['tactic']}]"
            )
            mapped_technique = mitre_data.get("technique", "")
            if mapped_technique:
                # Add to technique_counts (extend dict if new key)
                if mapped_technique not in technique_counts:
                    technique_counts[mapped_technique] = 0
                technique_counts[mapped_technique] += 1
                # Add to IOC set
                SIM_STATE["ioc_techniques"].add(mapped_technique)

        # ------------------------------------------
        # THREAT LEVEL ANALYSIS
        # ------------------------------------------
        # threat_level derived from risk_score_live above;
        # override to CRITICAL if node count is severe
        if (
            current_compromised >= 5
            and SIM_STATE["high_severity_events"] >= 8
        ):
            threat_level = "CRITICAL"

        # RISK SCORING

        SIM_STATE["risk_score"] = (
            (compromised_count * 70)
            + (SIM_STATE["critical_alerts"] * 12)
            + (SIM_STATE["high_severity_events"] * 8)
            + (SIM_STATE["lateral_movement_count"] * 35)
            + (SIM_STATE["discovery_events"] * 15)
            + (SIM_STATE["recon_events"] * 10)
        )

        SIM_STATE["incident_priority"] = get_incident_priority(SIM_STATE["risk_score"])

        alert_fatigue_score = get_alert_fatigue_score(
            (
                SIM_STATE["critical_alerts"]
                + (SIM_STATE["high_severity_events"] * 0.5)
                + (SIM_STATE["lateral_movement_count"] * 0.75)
            ),
            step + 1
        )

        SIM_STATE["incident_status"] = get_incident_status(
            SIM_STATE["risk_score"],
            compromised_count
        )

        SIM_STATE["attacker_profile"] = get_attacker_profile(
            SIM_STATE["risk_score"],
            SIM_STATE["lateral_movement_count"]
        )

        estimated_dwell_time = get_dwell_time(
            compromised_count
        )

        SIM_STATE["soc_recommendation"] = get_soc_recommendation(
            SIM_STATE["incident_priority"]
        )

        attack_success_rate = get_attack_success_rate(
            SIM_STATE["successful_attacks"],
            SIM_STATE["attack_attempts"]
        )

        dominant_technique = get_dominant_technique(
            technique_counts
        )


        # ------------------------------------------
        # ATTACK PROGRESSION ENGINE
        # ------------------------------------------

        if compromised_count == 0:
            attack_stage = "Recon"

        elif compromised_count <= 1:
            if SIM_STATE["persistence_score"] >= 4:
                attack_stage = "Initial Access"
            else:
                attack_stage = "Discovery"

        elif compromised_count <= 3:
            if SIM_STATE["lateral_movement_count"] >= 2:
                attack_stage = "Lateral Movement"
            else:
                attack_stage = "Initial Access"

        elif compromised_count <= 5:
            if SIM_STATE["persistence_score"] >= 10:
                attack_stage = "Persistence"
            else:
                attack_stage = "Lateral Movement"

        else:
            attack_stage = "Persistence"

        if attack_stage == "Persistence":
            SIM_STATE["persistence_score"] += max(
                1,
                3 - (SIM_STATE["successful_defenses"] * 0.08)
            )

        elif attack_stage == "Lateral Movement":
            SIM_STATE["persistence_score"] += max(
                1,
                2 - (SIM_STATE["successful_defenses"] * 0.05)
            )

        elif attack_stage == "Initial Access":
            SIM_STATE["persistence_score"] += 1

        SIM_STATE["persistence_score"] -= (
            SIM_STATE["successful_defenses"] * 0.12
        )
        SIM_STATE["persistence_score"] -= (
            SIM_STATE["defense_actions_count"] * 0.05
        )

        SIM_STATE["persistence_score"] = max(
            SIM_STATE["persistence_score"],
            0
        )
        action_text += f" | Stage: {attack_stage}"
        action_text += f" | Threat: {threat_level}"
        kill_chain_stage = map_kill_chain(action_text)

        # ------------------------------------------
        # KILL CHAIN SYNCHRONIZATION
        # Align kill chain rendering with attack
        # progression engine for telemetry cohesion
        # ------------------------------------------
        if attack_stage == "Persistence":
            kill_chain_stage = "Persistence"
        elif attack_stage == "Lateral Movement":
            kill_chain_stage = "Lateral Movement"
        elif attack_stage == "Discovery":
            kill_chain_stage = "Discovery"
        elif attack_stage == "Initial Access":
            kill_chain_stage = "Initial Access"

        # ------------------------------------------
        # LIVE SOC COUNTERS
        # ------------------------------------------
        if threat_level == "CRITICAL":
            SIM_STATE["critical_alerts"] += 1

        if threat_level in ["HIGH", "CRITICAL"]:
            SIM_STATE["high_severity_events"] += 1

        SIM_STATE["anomaly_pressure_score"] += (
            (len(SIM_STATE["ioc_ports"]) * 1.5)
            + (len(SIM_STATE["ioc_techniques"]) * 2.5)
            + (SIM_STATE["critical_alerts"] * 0.8)
            + (SIM_STATE["high_severity_events"] * 0.5)
        )

        if threat_level == "CRITICAL":
            SIM_STATE["anomaly_pressure_score"] += 4

        elif threat_level == "HIGH":
            SIM_STATE["anomaly_pressure_score"] += 2

        # --------------------------------------------------
        # ANOMALY PRESSURE DECAY
        # --------------------------------------------------

        SIM_STATE["anomaly_pressure_score"] -= (
            SIM_STATE["successful_defenses"] * 0.12
        )

        SIM_STATE["anomaly_pressure_score"] = max(
            SIM_STATE["anomaly_pressure_score"],
            0
        )

        if "SQL Injection"     in action_text:
            sqli_detected += 1
        if "Active Scanning"   in action_text:
            SIM_STATE["recon_events"] += 1
        if "Service Discovery" in action_text:
            SIM_STATE["discovery_events"] += 1
        if "Remote Services"   in action_text:
            SIM_STATE["lateral_movement_count"] += 1

        # IOC correlation logic

        # --------------------------------------------------
        # THREAT VOLATILITY ENGINE
        # --------------------------------------------------

        SIM_STATE["threat_volatility_score"] += (
            (SIM_STATE["threat_momentum_score"] * 0.08)
            + (SIM_STATE["critical_alerts"] * 0.6)
            + (SIM_STATE["high_severity_events"] * 0.4)
            + (SIM_STATE["lateral_movement_count"] * 0.7)
        )

        SIM_STATE["threat_volatility_score"] -= (
            SIM_STATE["successful_defenses"] * 0.18
        )

        SIM_STATE["threat_volatility_score"] = max(
            SIM_STATE["threat_volatility_score"],
            0
        )

        # --------------------------------------------------
        # ADAPTIVE IOC CORRELATION ENGINE
        # --------------------------------------------------

        correlation_delta = 0

        # --------------------------------------------------
        # IOC DENSITY CONTRIBUTION
        # --------------------------------------------------

        correlation_delta += (
            len(SIM_STATE["ioc_techniques"]) * 1.8
        )

        correlation_delta += (
            len(SIM_STATE["ioc_ports"]) * 1.2
        )

        # --------------------------------------------------
        # ATTACK STAGE PROGRESSION
        # --------------------------------------------------

        if (
            "Recon" in SIM_STATE["observed_attack_stages"]
            and "Discovery" in SIM_STATE["observed_attack_stages"]
        ):
            correlation_delta += 4

        if (
            "Initial Access" in SIM_STATE["observed_attack_stages"]
            and "Lateral Movement" in SIM_STATE["observed_attack_stages"]
        ):
            correlation_delta += 6

        if (
            "Persistence" in SIM_STATE["observed_attack_stages"]
        ):
            correlation_delta += 8

        # --------------------------------------------------
        # THREAT SEVERITY CONTRIBUTION
        # --------------------------------------------------

        if threat_level == "CRITICAL":
            correlation_delta += 8

        elif threat_level == "HIGH":
            correlation_delta += 4

        # --------------------------------------------------
        # CAMPAIGN COMPLEXITY
        # --------------------------------------------------
        correlation_delta += (
            SIM_STATE["lateral_movement_count"] * 1.5
        )

        correlation_delta += (
            SIM_STATE["persistence_score"] * 0.4
        )

        # --------------------------------------------------
        # DEFENDER SUPPRESSION
        # --------------------------------------------------

        correlation_delta -= (
            SIM_STATE["successful_defenses"] * 0.6
        )

        correlation_delta = max(
            correlation_delta,
            0
        )

        SIM_STATE["threat_correlation_score"] += correlation_delta

        SIM_STATE["threat_correlation_score"] -= (
            SIM_STATE["successful_defenses"] * 0.25
        )
        SIM_STATE["threat_correlation_score"] = max(
            SIM_STATE["threat_correlation_score"],
            0
        )

        if threat_level == "CRITICAL":
            SIM_STATE["threat_momentum_score"] += max(
                1,
                4 - (SIM_STATE["successful_defenses"] * 0.15)
            )

        elif threat_level == "HIGH":
            SIM_STATE["threat_momentum_score"] += max(
                1,
                2 - (SIM_STATE["successful_defenses"] * 0.08)
            )

        if attack_stage == "Persistence":
            SIM_STATE["threat_momentum_score"] += max(
                2,
                5 - (SIM_STATE["defense_actions_count"] * 0.12)
            )

        elif attack_stage == "Lateral Movement":
            SIM_STATE["threat_momentum_score"] += max(
                1,
                3 - (SIM_STATE["successful_defenses"] * 0.10)
            )

        # ------------------------------------------
        # REWARD STABILIZATION — telemetry coupling
        # ------------------------------------------
        reward -= (SIM_STATE["threat_momentum_score"] * 0.015)
        reward -= (SIM_STATE["persistence_score"] * 0.02)
        reward += (SIM_STATE["successful_defenses"] * 0.08)

        # ------------------------------------------
        # THREAT MOMENTUM DECAY
        # ------------------------------------------
        SIM_STATE["threat_momentum_score"] -= (
            SIM_STATE["successful_defenses"] * 0.35
        )
        SIM_STATE["threat_momentum_score"] -= (
            SIM_STATE["defense_actions_count"] * 0.05
        )
        SIM_STATE["threat_momentum_score"] = max(
            SIM_STATE["threat_momentum_score"],
            0
        )

        # ALERT FATIGUE ESTIMATION
        if SIM_STATE["critical_alerts"] > 0:
            alert_fatigue_score = round(
                SIM_STATE["critical_alerts"] / max(step + 1, 1), 2
            )
        st.session_state.alert_fatigue_score = alert_fatigue_score

        # Accumulate reward after all modifications
        total_reward += reward

        # ------------------------------------------
        # FINAL LOG MESSAGE
        # ------------------------------------------
        explanation = explain_action(action, compromised_count, attack_result)

        event = build_event(
            actor="attacker" if action < env.node_count else "defender",
            node_id=node_id if action < env.node_count else -1,
            node_type=SIMULATION_NODES.get(node_id, "Unknown")
                if action < env.node_count else "Defender",
            service=target_system if action < env.node_count else "SOC",
            technique=technique_id,
            tactic=mitre_data.get("tactic", "")
                if mitre_data else "",
            mitre_name=mitre_data.get("name", "")
                if mitre_data else "",
            kill_chain=kill_chain_stage,
            threat=threat_level,
            port=attack_result.get("port")
                if attack_result and "port" in attack_result else None,
            cve=vuln_info.get("cve", "N/A"),
            cvss=vuln_info.get("cvss", None),
            status="success"
                if compromised_count > previous_compromised
                else "failed",
            vulnerability=attack_result.get("vulnerability")
                if attack_result else "",

            detection_signature=detection_info.get("signature", "N/A"),

            detection_severity=detection_info.get("severity", "N/A"),

            detection_confidence=detection_info.get("confidence", 0),

            timeline_weight=(
                SIM_STATE["threat_momentum_score"]
                + SIM_STATE["persistence_score"]
                + SIM_STATE["threat_correlation_score"]
            ),

            explanation=explanation,

            compromised_count=compromised_count,

            step=step
        )

        SIM_STATE["observed_attack_stages"].add(kill_chain_stage)

        # --------------------------------------------------
        # ADAPTIVE DETECTION CONFIDENCE ENGINE
        # --------------------------------------------------

        alert_confidence = 45

        # --------------------------------------------------
        # THREAT SEVERITY CONTRIBUTION
        # --------------------------------------------------

        if threat_level == "CRITICAL":
            alert_confidence += 25

        elif threat_level == "HIGH":
            alert_confidence += 15

        elif threat_level == "MEDIUM":
            alert_confidence += 8

        # --------------------------------------------------
        # ATTACK STAGE CONTRIBUTION
        # --------------------------------------------------

        if attack_stage == "Persistence":
            alert_confidence += 12

        elif attack_stage == "Lateral Movement":
            alert_confidence += 8

        elif attack_stage == "Initial Access":
            alert_confidence += 5

        # --------------------------------------------------
        # IOC / TELEMETRY CONTRIBUTION
        # --------------------------------------------------

        alert_confidence += (
            len(SIM_STATE["ioc_techniques"]) * 1.5
        )

        alert_confidence += (
            len(SIM_STATE["ioc_ports"]) * 1.0
        )

        alert_confidence += (
            SIM_STATE["critical_alerts"] * 0.6
        )

        # --------------------------------------------------
        # SOC PERFORMANCE ADJUSTMENT
        # --------------------------------------------------

        alert_confidence += (
            SIM_STATE["successful_defenses"] * 0.4
        )

        alert_confidence -= (
            SIM_STATE["failed_defenses"] * 0.3
        )

        # --------------------------------------------------
        # CONFIDENCE STABILIZATION
        # --------------------------------------------------

        confidence_noise = np.random.randint(-4, 5)
        alert_confidence += confidence_noise
        alert_confidence = max(
            25,
            min(alert_confidence, 100)
        )

        alert_confidence_total += alert_confidence
        alert_count += 1

        SIM_STATE["structured_events"].append(event)
        soc_engine.ingest(event, reward)
        ioc_engine.ingest(event)
        log_message = format_event_log(event)

        SIM_STATE["event_logs"].insert(0, log_message)

        SIM_STATE["timeline_data"].insert(0, {
            "Time":  timestamp,
            "Stage": kill_chain_stage,
            "Threat": threat_level,
            "Event": action_text,
        })

        SIM_STATE["threat_history"].append(SIM_STATE["critical_alerts"])
        if len(SIM_STATE["threat_history"]) >= 2:
            pass
        SIM_STATE["compromise_history"].append(compromised_count)
        SIM_STATE["step_history"].append(step)

        # ------------------------------------------
        # NODE COLORS
        # ------------------------------------------
        colors = [
            "#ff3b30" if obs[i] == 1 else "#34c759"
            for i in range(env.node_count)
        ]

        # ------------------------------------------
        # CREATE FIGURE
        # ------------------------------------------
        fig, ax = plt.subplots(figsize=(12, 7))
        fig.patch.set_facecolor("#f8fafc")
        ax.set_facecolor("#f8fafc")

        nx.draw_networkx_nodes(
            G, pos, node_color=colors,
            node_size=2600, edgecolors="black",
            linewidths=2, ax=ax
        )

        nx.draw_networkx_edges(
            G, pos, edge_color="gray",
            width=2, ax=ax
        )

        nx.draw_networkx_labels(
            G, pos, labels=labels,
            font_size=10,
            font_weight="bold",
            font_color="black",
            ax=ax
        )

        ax.set_title(
            f"Cyber Attack Simulation — Step {step}",
            fontsize=26,
            color="black",
            fontweight="bold",
            pad=20
        )

        ax.axis("off")
        plt.tight_layout()

        with graph_placeholder.container():
            st.markdown(
                '<div class="graph-card">',
                unsafe_allow_html=True
            )

            st.pyplot(fig)

            st.markdown(
                '</div>',
                unsafe_allow_html=True
            )


        reward_metric.metric("Total Reward",    round(total_reward, 2))
        comp_metric.metric("Compromised Nodes", compromised_count)
        step_metric.metric("Simulation Step",   step)
        threat_metric.metric("Threat Level",    threat_level)



        # ------------------------------------------
        # LIVE ANALYTICS CHARTS
        # ------------------------------------------
        with chart_placeholder.container():
            st.markdown("## 📈 Threat Analytics")

            chart_df = build_chart_df(
                SIM_STATE["step_history"],
                SIM_STATE["threat_history"],
                SIM_STATE["compromise_history"]
            )

            st.line_chart(
                chart_df.set_index("Step"),
                use_container_width=True
            )

        # ------------------------------------------
        # LIVE LOG
        # ------------------------------------------
        log_placeholder.text_area(
            "Live Threat Feed",
            "\n".join(SIM_STATE["event_logs"][-12:]),
            height=260,
            disabled=True,
            key=f"soc_live_feed_{step}"
        )

        # ------------------------------------------
        # Update IOC Intelligence panels live
        # ------------------------------------------
        port_list = [f"Port {p}" for p in sorted(SIM_STATE['ioc_ports'])]
        tech_list = sorted(SIM_STATE["ioc_techniques"])
        ioc_ports_placeholder.code(
            "\n".join(port_list) if port_list else "No ports observed yet.",
            language="text"
        )
        ioc_tech_placeholder.code(
            "\n".join(tech_list) if tech_list else "No techniques observed yet.",
            language="text"
        )

        # Update Threat Hunt placeholders live
        hunt1_placeholder.metric(
            "Unique Techniques",
            len(SIM_STATE["ioc_techniques"])
        )
        hunt2_placeholder.metric(
            "Observed Ports",
            len(SIM_STATE["ioc_ports"])
        )
        hunt3_placeholder.metric(
            "Compromised Assets",
            len(SIM_STATE["compromised_assets"])
        )

        # ------------------------------------------
        # SPEED — at loop level
        # ------------------------------------------
        time.sleep(speed)

if st.session_state.simulation_started:

    # --------------------------------------------------
    # SOC DASHBOARD METRICS
    # --------------------------------------------------
    render_kpi_cards(
        SIM_STATE["critical_alerts"],
        sqli_detected,
        SIM_STATE["recon_events"],
        SIM_STATE["discovery_events"],
        SIM_STATE["risk_score"],
        SIM_STATE["incident_priority"],
        SIM_STATE["incident_status"],
        attack_success_rate,
        defense_effectiveness,
        SIM_STATE["attacker_profile"],
        estimated_dwell_time,
        SIM_STATE["high_severity_events"]
    )
else:
    st.info("▶ Run the simulation to populate IOC intelligence.")

# Performance recalc at module level
if SIM_STATE["attack_attempts"] > 0:
    attack_success_rate = (SIM_STATE["successful_attacks"] / SIM_STATE["attack_attempts"]) * 100
else:
    attack_success_rate = 0


# ------------------------------------------
# ATTACK TIMELINE
# ------------------------------------------
st.markdown("## 📊 Attack Timeline")
if st.session_state.simulation_started:
    selected_threat = st.selectbox(
        "Filter Threat Level",
        ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        key="threat_filter"
    )

    fig_mitre = None
    timeline_df = pd.DataFrame()

    if SIM_STATE["timeline_data"]:
        timeline_df = build_timeline_df(SIM_STATE["structured_events"])

        if "timeline_weight" in timeline_df.columns:
            timeline_df = timeline_df.sort_values(
                by="timeline_weight",
                ascending=False
            )
        threat_numeric = {
            "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
        }

        timeline_df["ThreatScore"] = timeline_df["Threat"].map(threat_numeric)
        timeline_df = filter_timeline(
            timeline_df,
            selected_threat
        )
        st.dataframe(timeline_df.head(25), use_container_width=True)
        fig_trend = px.line(
            timeline_df.head(25),
            x="Time",
            y="ThreatScore",
            color="Stage",
            title="Threat Escalation Trend"
        )
        st.plotly_chart(fig_trend, use_container_width=True)
        mitre_df = build_mitre_table(
            technique_counts
        )
        st.markdown("## 🎯 MITRE ATT&CK Technique Frequency")
        st.dataframe(mitre_df, use_container_width=True)
        fig_mitre = build_mitre_pie(
            technique_counts
        )

    if fig_mitre is not None:
        st.plotly_chart(
            fig_mitre,
            use_container_width=True
        )

    if not timeline_df.empty:
        csv_data = export_soc_report(
            timeline_df
        )

        st.download_button(
            label="📥 Download SOC Report",
            data=csv_data,
            file_name="soc_attack_timeline.csv",
            mime="text/csv",
            key="download_soc_report"
        )

else:
    st.info("▶ Run the simulation to populate the Attack Timeline.")

# --------------------------------------------------
# POST-SIMULATION: Final priority / status recalc
# --------------------------------------------------

if (
    compromised_count >= 5
    or SIM_STATE["risk_score"] >= 700
    or SIM_STATE["lateral_movement_count"] >= 5
):
    SIM_STATE["incident_priority"] = "P1"

elif (
    compromised_count >= 3
    or SIM_STATE["risk_score"] >= 350
    or SIM_STATE["discovery_events"] >= 5
):
    SIM_STATE["incident_priority"] = "P2"

else:
    SIM_STATE["incident_priority"] = "LOW"

SIM_STATE["incident_status"] = "MONITORING"

if (
    compromised_count >= 5
    or (
        SIM_STATE["lateral_movement_count"] >= 4
        and SIM_STATE["high_severity_events"] >= 10
    )
):
    SIM_STATE["incident_status"] = "BREACH CONFIRMED"

elif (
    SIM_STATE["risk_score"] >= 250
    or compromised_count >= 3
):
    SIM_STATE["incident_status"] = "ACTIVE INCIDENT"

estimated_dwell_time = (
    (compromised_count * 8)
    + (SIM_STATE["lateral_movement_count"] * 6)
    + (SIM_STATE["discovery_events"] * 3)
)

campaign_diversity_score = min(
    100,
    (
        len(SIM_STATE["ioc_techniques"]) * 6
    )
    + (
        len(SIM_STATE["observed_attack_stages"]) * 10
    )
    + (
        SIM_STATE["lateral_movement_count"] * 3
    )
)
SIM_STATE["anomaly_pressure_score"] = min(
    SIM_STATE["anomaly_pressure_score"],
    100
)
SIM_STATE["threat_volatility_score"] = min(
    SIM_STATE["threat_volatility_score"],
    100
)
SIM_STATE["containment_pressure_score"] = min(
    SIM_STATE["containment_pressure_score"],
    100
)
SIM_STATE["threat_momentum_score"] = min(
    SIM_STATE["threat_momentum_score"],
    100
)
SIM_STATE["threat_correlation_score"] = min(
    SIM_STATE["threat_correlation_score"],
    100
)
alert_fatigue_score = min(
    alert_fatigue_score,
    100
)

if alert_count > 0:
    average_alert_confidence = (
        alert_confidence_total / alert_count
    )
    average_alert_confidence = min(
        average_alert_confidence,
        100
    )
else:
    average_alert_confidence = 0

soc_stability_index = max(
    25,
    100
    - (compromised_count * 8)
    - (SIM_STATE["critical_alerts"] * 1.5)
    - (SIM_STATE["threat_momentum_score"] * 0.18)
    - (SIM_STATE["anomaly_pressure_score"] * 0.12)
)
research_consistency_score = max(
    0,
    100
    - (SIM_STATE["threat_volatility_score"] * 0.45)
    - (SIM_STATE["anomaly_pressure_score"] * 0.30)
    - (SIM_STATE["containment_pressure_score"] * 0.20)
)
research_consistency_score += (
    average_alert_confidence * 0.05
)

research_consistency_score = min(
    research_consistency_score,
    100
)

if compromised_count <= 1:
    SIM_STATE["attacker_profile"] = "Opportunistic Scanner"

elif SIM_STATE["recon_events"] >= 5 and compromised_count <= 3:
    SIM_STATE["attacker_profile"] = "Reconnaissance Operator"

elif (
    SIM_STATE["lateral_movement_count"] >= 4
    or SIM_STATE["persistence_score"] >= 12
):
    SIM_STATE["attacker_profile"] = "Advanced Persistent Threat"

elif SIM_STATE["discovery_events"] >= 6:
    SIM_STATE["attacker_profile"] = "Internal Network Explorer"

else:
    SIM_STATE["attacker_profile"] = "Targeted Adversary"

# ------------------------------------------
# THREAT ATTRIBUTION ENGINE
# ------------------------------------------

if (
    SIM_STATE["persistence_score"] >= 12
    and SIM_STATE["threat_correlation_score"] >= 40
):
    threat_actor_confidence = 95

elif (
    SIM_STATE["lateral_movement_count"] >= 4
    and campaign_diversity_score >= 50
):
    threat_actor_confidence = 82

elif (
    SIM_STATE["recon_events"] >= 5
    and SIM_STATE["discovery_events"] >= 5
):
    threat_actor_confidence = 68

else:
    threat_actor_confidence = 45


if threat_actor_confidence >= 90:
    threat_actor_type = "Nation-State APT"

elif threat_actor_confidence >= 75:
    threat_actor_type = "Organized Cybercrime"

elif threat_actor_confidence >= 60:
    threat_actor_type = "Advanced Intrusion Actor"

else:
    threat_actor_type = "Opportunistic Threat Actor"

# ------------------------------------------
# CAMPAIGN CLASSIFICATION ENGINE
# ------------------------------------------

if (
    SIM_STATE["recon_events"] >= 6
    and compromised_count <= 2
):
    SIM_STATE["campaign_type"] = "Reconnaissance Campaign"

elif (
    SIM_STATE["lateral_movement_count"] >= 4
    and compromised_count >= 3
):
    SIM_STATE["campaign_type"] = "Lateral Expansion Campaign"

elif (
    SIM_STATE["persistence_score"] >= 12
    and SIM_STATE["threat_correlation_score"] >= 40
):
    SIM_STATE["campaign_type"] = "Persistent Intrusion Campaign"

elif (
    SIM_STATE["threat_momentum_score"] >= 60
    and campaign_diversity_score >= 50
):
    SIM_STATE["campaign_type"] = "Coordinated Multi-Stage Campaign"

else:
    SIM_STATE["campaign_type"] = "General Intrusion Campaign"

if compromised_count >= 5:
    SIM_STATE["soc_recommendation"] = "Initiate Enterprise Incident Response"

elif SIM_STATE["lateral_movement_count"] >= 4:
    SIM_STATE["soc_recommendation"] = "Contain Lateral Movement Immediately"

elif SIM_STATE["discovery_events"] >= 5:
    SIM_STATE["soc_recommendation"] = "Investigate Internal Reconnaissance Activity"

elif SIM_STATE["recon_events"] >= 5:
    SIM_STATE["soc_recommendation"] = "Increase External Monitoring"

elif SIM_STATE["incident_priority"] == "P2":
    SIM_STATE["soc_recommendation"] = "Escalate To SOC Team"

else:
    SIM_STATE["soc_recommendation"] = "Continue Monitoring"

if st.session_state.simulation_started:
    st.success("Simulation Completed")
    st.session_state.simulation_complete = True

st.markdown("## 📋 Executive SOC Summary")

if st.session_state.simulation_started:

    # Use dominant_technique variable, not technique_id
    if technique_counts and any(technique_counts.values()):
        dominant_technique = max(
            technique_counts,
            key=technique_counts.get
        )
    else:
        dominant_technique = "N/A"

    # --------------------------------------------------
    # THREAT SOPHISTICATION ENGINE
    # --------------------------------------------------

    threat_sophistication_score = min(
        100,
        (
            SIM_STATE["threat_momentum_score"] * 0.35
        )
        + (
            SIM_STATE["persistence_score"] * 1.8
        )
        + (
            SIM_STATE["lateral_movement_count"] * 4
        )
        + (
            len(SIM_STATE["ioc_techniques"]) * 3
        )
        + (
            campaign_diversity_score * 0.25
        )
    )

    # --------------------------------------------------
    # ANALYST VERDICT ENGINE
    # --------------------------------------------------

    if threat_sophistication_score >= 85:
        analyst_verdict = (
            "Advanced multi-stage intrusion campaign "
            "with coordinated persistence activity."
        )

    elif threat_sophistication_score >= 65:
        analyst_verdict = (
            "Highly capable attacker exhibiting "
            "structured lateral movement behavior."
        )

    elif threat_sophistication_score >= 40:
        analyst_verdict = (
            "Moderately sophisticated attack chain "
            "with observable escalation patterns."
        )

    else:
        analyst_verdict = (
            "Low-complexity opportunistic attack activity."
        )

    # --------------------------------------------------
    # CAMPAIGN CLASSIFICATION ENGINE
    # --------------------------------------------------

    if (
        SIM_STATE["persistence_score"] >= 12
        and SIM_STATE["lateral_movement_count"] >= 4
    ):
        campaign_classification = (
            "Persistent Lateral Movement Campaign"
        )

    elif (
        SIM_STATE["critical_alerts"] >= 8
        and SIM_STATE["threat_momentum_score"] >= 60
    ):
        campaign_classification = (
            "High-Impact Escalation Campaign"
        )

    elif (
        SIM_STATE["recon_events"] >= 5
        and SIM_STATE["discovery_events"] >= 4
    ):
        campaign_classification = (
            "Reconnaissance-Led Intrusion Campaign"
        )

    else:
        campaign_classification = (
            "Generalized Opportunistic Threat Activity"
        )

    # --------------------------------------------------
    # SOC ESCALATION REASONING
    # --------------------------------------------------

    if SIM_STATE["incident_priority"] == "CRITICAL":
        escalation_reason = (
            "Critical attack indicators exceed "
            "SOC containment thresholds."
        )

    elif SIM_STATE["incident_priority"] == "HIGH":
        escalation_reason = (
            "Sustained attacker momentum detected "
            "across multiple attack stages."
        )

    elif SIM_STATE["incident_priority"] == "MEDIUM":
        escalation_reason = (
            "Moderate threat activity requiring "
            "continued analyst monitoring."
        )

    else:
        escalation_reason = (
            "Threat activity remains within "
            "manageable SOC thresholds."
        )

    # --------------------------------------------------
    # THREAT ACTOR MATURITY ENGINE
    # --------------------------------------------------
    threat_actor_maturity = min(
        100,
        (
            threat_sophistication_score * 0.45
        )
        + (
            SIM_STATE["persistence_score"] * 1.6
        )
        + (
            SIM_STATE["threat_momentum_score"] * 0.25
        )
        + (
            campaign_diversity_score * 0.18
        )
    )

    # --------------------------------------------------
    # OPERATIONAL DISCIPLINE ENGINE
    # --------------------------------------------------

    if threat_actor_maturity >= 85:
        operational_discipline = (
            "Highly disciplined attacker with "
            "coordinated multi-stage behavior."
        )
    elif threat_actor_maturity >= 65:
        operational_discipline = (
            "Structured operational behavior with "
            "persistent attack coordination."
        )

    elif threat_actor_maturity >= 40:
        operational_discipline = (
            "Moderately organized attack activity "
            "with limited persistence discipline."
        )

    else:
        operational_discipline = (
            "Low-discipline opportunistic attack behavior."
        )

    # --------------------------------------------------
    # ATTACKER INTENT PROFILING
    # --------------------------------------------------

    if (
        SIM_STATE["persistence_score"] >= 12
        and SIM_STATE["lateral_movement_count"] >= 5
    ):
        attacker_intent = (
            "Long-term persistent infrastructure compromise."
        )

    elif (
        SIM_STATE["critical_alerts"] >= 8
        and SIM_STATE["threat_momentum_score"] >= 70
    ):
        attacker_intent = (
            "Aggressive high-impact operational disruption."
        )

    elif (
        SIM_STATE["recon_events"] >= 6
        and SIM_STATE["discovery_events"] >= 5
    ):
        attacker_intent = (
            "Strategic reconnaissance and network mapping."
        )

    else:
        attacker_intent = (
            "General opportunistic exploitation activity."
        )

    # --------------------------------------------------
    # ADVERSARY BEHAVIORAL NARRATIVE
    # --------------------------------------------------

    adversary_behavior = (
        f"The attacker demonstrated {campaign_classification.lower()} "
        f"with {SIM_STATE['attacker_profile'].lower()} characteristics. "

        f"Operational analysis indicates "
        f"{operational_discipline.lower()} "

        f"Observed intent suggests "
        f"{attacker_intent.lower()}"
    )

    # --------------------------------------------------
    # BUSINESS IMPACT ENGINE
    # --------------------------------------------------

    business_impact_score = min(
        100,
        (
            compromised_count * 10
        )
        + (
            SIM_STATE["critical_alerts"] * 4
        )
        + (
            SIM_STATE["persistence_score"] * 1.5
        )
        + (
            SIM_STATE["threat_momentum_score"] * 0.4
        )
    )

    # --------------------------------------------------
    # EXECUTIVE IMPACT ASSESSMENT
    # --------------------------------------------------

    if business_impact_score >= 85:
        executive_impact = (
            "Enterprise-wide operational disruption risk."
        )

    elif business_impact_score >= 65:
        executive_impact = (
            "Critical infrastructure and business workflow exposure."
        )

    elif business_impact_score >= 40:
        executive_impact = (
            "Moderate operational impact requiring containment."
        )

    else:
        executive_impact = (
            "Limited operational disruption currently observed."
        )

    # --------------------------------------------------
    # INCIDENT RESPONSE PRIORITY ENGINE
    # --------------------------------------------------

    if (
        SIM_STATE["incident_priority"] == "CRITICAL"
        or business_impact_score >= 85
    ):
        response_priority = (
            "Immediate enterprise incident response activation."
        )

    elif (
        SIM_STATE["incident_priority"] == "HIGH"
        or business_impact_score >= 65
    ):
        response_priority = (
            "Escalated SOC containment and threat hunting."
        )

    elif (
        SIM_STATE["incident_priority"] == "MEDIUM"
    ):
        response_priority = (
            "Focused investigation and containment monitoring."
        )

    else:
        response_priority = (
            "Routine SOC monitoring and telemetry review."
        )

    # --------------------------------------------------
    # CONTAINMENT URGENCY ENGINE
    # --------------------------------------------------

    containment_urgency = min(
        100,
        (
            business_impact_score * 0.5
        )
        + (
            SIM_STATE["threat_volatility_score"] * 0.3
        )
        + (
            SIM_STATE["containment_pressure_score"] * 0.2
        )
    )

    # --------------------------------------------------
    # EXECUTIVE DECISION NARRATIVE
    # --------------------------------------------------

    executive_decision_narrative = (
        f"Operational analysis indicates "
        f"{executive_impact.lower()} "

        f"Containment urgency currently assessed at "
        f"{containment_urgency:.1f}/100. "

        f"Recommended response posture: "
        f"{response_priority.lower()}"
    )

    # --------------------------------------------------
    # CAMPAIGN PROGRESSION NARRATIVE
    # --------------------------------------------------
    campaign_progression = (
        f"The attack campaign evolved through "
        f"{len(SIM_STATE['observed_attack_stages'])} observed stages "
        f"with {SIM_STATE['critical_alerts']} critical alerts "
        f"and {SIM_STATE['lateral_movement_count']} lateral movement events. "
        f"Threat progression reached the "
        f"{attack_stage.lower()} phase "
        f"with a volatility score of "
        f"{SIM_STATE['threat_volatility_score']:.1f}/100."
    )

    # --------------------------------------------------
    # SOC INVESTIGATION NARRATIVE
    # --------------------------------------------------

    soc_investigation_narrative = (
        f"SOC telemetry identified "
        f"{len(SIM_STATE['ioc_techniques'])} attack techniques "
        f"across {len(SIM_STATE['ioc_ports'])} observed ports. "
        f"Detection analytics produced "
        f"{average_alert_confidence:.1f}% average confidence "
        f"with {SIM_STATE['threat_correlation_score']:.1f}/100 "
        f"threat correlation intensity."
    )

    # --------------------------------------------------
    # EXECUTIVE THREAT BRIEFING
    # --------------------------------------------------

    executive_threat_briefing = (
        f"{campaign_classification}. "
        f"{executive_impact} "
        f"{analyst_verdict} "
        f"Recommended executive response: "
        f"{response_priority}"
    )

    # --------------------------------------------------
    # INCIDENT CHRONOLOGY NARRATIVE
    # --------------------------------------------------

    incident_chronology = (
        f"Initial activity began with "
        f"{SIM_STATE['recon_events']} reconnaissance indicators, "
        f"followed by {SIM_STATE['discovery_events']} discovery events "
        f"and escalation into "
        f"{attack_stage.lower()} operations."
    )

    # --------------------------------------------------
    # NARRATIVE QUALITY STABILIZATION
    # --------------------------------------------------

    campaign_progression = campaign_progression.strip()
    soc_investigation_narrative = (
        soc_investigation_narrative.strip()
    )

    executive_threat_briefing = (
        executive_threat_briefing.strip()
    )

    incident_chronology = incident_chronology.strip()

    # --------------------------------------------------
    # RESEARCH CONFIDENCE INDEX
    # --------------------------------------------------

    research_confidence_index = min(
        100,
        (
            average_alert_confidence * 0.30
        )
        + (
            SIM_STATE["threat_correlation_score"] * 0.25
        )
        + (
            research_consistency_score * 0.25
        )
        + (
            soc_stability_index * 0.20
        )
    )

    # --------------------------------------------------
    # SIMULATION RELIABILITY ASSESSMENT
    # --------------------------------------------------

    if research_confidence_index >= 85:
        simulation_reliability = (
            "High-confidence simulation telemetry "
            "with stable SOC analytics."
        )

    elif research_confidence_index >= 65:
        simulation_reliability = (
            "Moderately reliable simulation behavior "
            "with consistent threat analytics."
        )

    elif research_confidence_index >= 40:
        simulation_reliability = (
            "Variable simulation conditions with "
            "partially stable threat telemetry."
        )

    else:
        simulation_reliability = (
            "Low-confidence telemetry conditions "
            "requiring additional calibration."
        )

    # --------------------------------------------------
    # DASHBOARD OPERATIONAL STATE
    # --------------------------------------------------

    if st.session_state.simulation_started:
        dashboard_operational_state = (
            "Operational SOC intelligence environment active."
        )
    else:
        dashboard_operational_state = (
            "Awaiting simulation execution."
        )

    # --------------------------------------------------
    # RESEARCH SUMMARY NARRATIVE
    # --------------------------------------------------

    research_summary_narrative = (
        f"The Cyber-MARL simulation generated "
        f"{alert_count} structured alerts "
        f"across {len(SIM_STATE['observed_attack_stages'])} "
        f"attack stages with "
        f"{research_confidence_index:.1f}/100 "
        f"research confidence. "
        f"Simulation reliability assessment indicates "
        f"{simulation_reliability.lower()}"
    )

    st.info(
        f"""
        Total Risk Score: {SIM_STATE["risk_score"]}

        Incident Priority: {SIM_STATE["incident_priority"]}

        Incident Status: {SIM_STATE["incident_status"]}

        Compromised Nodes: {compromised_count}

        Dominant Threat Technique: {dominant_technique}

        Estimated Dwell Time: {estimated_dwell_time} mins

        Detection Confidence: {average_alert_confidence:.1f}%

        Campaign Diversity Score: {campaign_diversity_score}

        Anomaly Pressure Score: {SIM_STATE["anomaly_pressure_score"]}/100

        Threat Volatility Score: {SIM_STATE["threat_volatility_score"]}/100

        Containment Pressure Score: {SIM_STATE["containment_pressure_score"]}/100

        Threat Momentum Score: {SIM_STATE["threat_momentum_score"]}/100

        SOC Stability Index: {soc_stability_index:.1f}/100

        Research Consistency Score: {research_consistency_score:.1f}/100

        Threat Correlation Score: {SIM_STATE["threat_correlation_score"]}/100

        Threat Sophistication Score: {threat_sophistication_score}/100

        Campaign Classification: {campaign_classification}

        Threat Actor Maturity: {threat_actor_maturity:.1f}/100

        Operational Discipline: {operational_discipline}

        Attacker Intent: {attacker_intent}

        Adversary Behavioral Narrative:
        {adversary_behavior}

        Analyst Verdict: {analyst_verdict}

        SOC Escalation Reasoning: {escalation_reason}

        Business Impact Score: {business_impact_score:.1f}/100

        Executive Impact Assessment: {executive_impact}

        Response Priority: {response_priority}

        Containment Urgency: {containment_urgency:.1f}/100

        Executive Decision Narrative:
        {executive_decision_narrative}

        Campaign Progression Narrative:
        {campaign_progression}

        SOC Investigation Narrative:
        {soc_investigation_narrative}

        Executive Threat Briefing:
        {executive_threat_briefing}

        Incident Chronology:
        {incident_chronology}

        Research Confidence Index:
        {research_confidence_index:.1f}/100

        Simulation Reliability:
        {simulation_reliability}

        Dashboard Operational State:
        {dashboard_operational_state}

        Research Summary Narrative:
        {research_summary_narrative}

        Threat Actor Confidence: {threat_actor_confidence}%

        Threat Actor Type: {threat_actor_type}

        Campaign Type: {SIM_STATE["campaign_type"]}

        Attacker Profile: {SIM_STATE["attacker_profile"]}

        SOC Recommendation: {SIM_STATE["soc_recommendation"]}
        """
    )

else:
    st.info(
        "▶ Run the simulation to generate the Executive SOC Summary."
    )
