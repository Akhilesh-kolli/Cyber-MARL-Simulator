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

# --------------------------------------------------
# AI DECISION EXPLANATION
# --------------------------------------------------

def explain_action(
    action,
    compromised_count,
    attack_result=None
):

    # ------------------------------------------
    # ATTACKER EXPLANATION
    # ------------------------------------------
    if action < env.node_count:

        # DVWA target
        if action == 1:

            if attack_result and attack_result.get(
                "vulnerability"
            ):

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

        # MySQL target
        elif action == 2:

            return (
                "Attacker targeted MySQL because "
                "database services may expose "
                "credential or lateral movement opportunities."
            )

        # Generic attack
        return (
            "Attacker selected this node based on "
            "reinforcement-learning reward optimization "
            "and compromise probability."
        )

    # ------------------------------------------
    # DEFENDER EXPLANATION
    # ------------------------------------------
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

st.markdown("""
<style>

/* =======================================================
   GLOBAL
======================================================= */

.stApp {
    background: linear-gradient(to right, #0b1220, #111827);
    color: #f8fafc;
    font-family: "Segoe UI", sans-serif;
}

[data-testid="stAppViewContainer"] {
    background: linear-gradient(to right, #0b1220, #111827);
}

.main .block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

/* =======================================================
   HEADER / TOOLBAR
======================================================= */

header {
    background: transparent !important;
}

header * {
    color: #f8fafc !important;
}

/* =======================================================
   SIDEBAR
======================================================= */

section[data-testid="stSidebar"] {
    background: #111827;
    border-right: 1px solid #1f2937;
}

section[data-testid="stSidebar"] * {
    color: #f3f4f6 !important;
}

/* =======================================================
   BUTTONS
======================================================= */

.stButton > button {
    background-color: #2563eb !important;
    color: white !important;
    border-radius: 10px !important;
    border: none !important;
    padding: 0.5rem 1rem !important;
    font-weight: 600 !important;
}

.stButton > button:hover {
    background-color: #1d4ed8 !important;
    color: white !important;
}

/* DOWNLOAD BUTTON */

.stDownloadButton > button {
    background-color: #2563eb !important;
    color: white !important;
    border-radius: 10px !important;
    border: none !important;
    font-weight: 600 !important;
}

.stDownloadButton > button:hover {
    background-color: #1d4ed8 !important;
    color: white !important;
}

/* =======================================================
   METRIC CARDS
======================================================= */

[data-testid="metric-container"] {
    background: #111827 !important;
    border: 1px solid #1f2937 !important;
    border-radius: 14px !important;
    padding: 18px !important;
    box-shadow: 0 0 12px rgba(0,255,255,0.08);
}

[data-testid="stMetricValue"] {
    color: #ffffff !important;
    font-weight: 700 !important;
    opacity: 1 !important;
}

[data-testid="stMetricLabel"] {
    color: #e5e7eb !important;
    opacity: 1 !important;
}

/* =======================================================
   HEADINGS
======================================================= */

h1, h2, h3, h4 {
    color: #f3f4f6 !important;
}

/* =======================================================
   DATAFRAME / TABLE
======================================================= */

[data-testid="stDataFrame"] {
    border: 1px solid #1f2937;
    border-radius: 12px;
}

/* LIVE LOG TEXT AREA */

textarea {
    background-color: #111827 !important;
    color: #f8fafc !important;
    border: 1px solid #1f2937 !important;
    border-radius: 12px !important;
    opacity: 1 !important;
    -webkit-text-fill-color: #f8fafc !important;
}

/* =======================================================
   CODE BLOCKS
======================================================= */

.stCodeBlock {
    border-radius: 12px;
    border: 1px solid #1f2937;
}

/* =======================================================
   ALERT BOXES
======================================================= */

[data-testid="stAlert"] {
    border-radius: 12px;
}

/* =======================================================
   GRAPH PANEL
======================================================= */

.graph-card {
    background: #111827;
    padding: 20px;
    border-radius: 16px;
    border: 1px solid #1f2937;
}

/* =======================================================
   SPINNER / RUNNING STATUS
======================================================= */
[data-testid="stStatusWidget"] {
    background: #111827 !important;
    border: 1px solid #1f2937 !important;
    border-radius: 8px !important;
}

[data-testid="stStatusWidget"] * {
    color: #f8fafc !important;
}

/* =======================================================
   FOOTER
======================================================= */

footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)
# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------
st.set_page_config(
    page_title="Cyber MARL Threat Simulation Platform",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------------------------
# HEADER
# --------------------------------------------------
st.markdown("""
<h1 style="
color:#f3f4f6;
font-size:50px;
margin-bottom:0px;
">
🛡️ Cyber MARL Threat Simulation Platform
</h1>
""", unsafe_allow_html=True)

st.markdown("""
<p style="
font-size:20px;
color:#cbd5e1;
margin-top:0px;
margin-bottom:30px;
">
Real-time attacker vs defender cyber simulation using
Multi-Agent Reinforcement Learning.
</p>
""", unsafe_allow_html=True)

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
pos = nx.spring_layout(
    G,
    seed=42,
    k=1.3
)

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

st.sidebar.markdown("---")

st.sidebar.success("🟢 Green Nodes = Secure")
st.sidebar.error("🔴 Red Nodes = Compromised")

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

log_placeholder = st.empty()

event_logs = []

timeline_data = []

threat_history = []
compromise_history = []
step_history = []
compromised_count = 0

alert_fatigue_score = 0
soc_recommendation = "Monitoring"
attacker_profile = "Unknown"
estimated_dwell_time = 0
incident_status = "MONITORING"
technique_id = "N/A"

ioc_ips = set()
ioc_ports = set()
ioc_techniques = set()
compromised_assets = set()


st.markdown("## 🕵️ Threat Hunt Summary")
hunt1, hunt2, hunt3 = st.columns(3)

with hunt1:
    st.metric(
        "Unique Techniques",
        len(set(ioc_techniques))
    )

with hunt2:
    st.metric(
        "Observed Ports",
        len(set(ioc_ports))
    )

with hunt3:
    st.metric(
        "Compromised Assets",
        len(compromised_assets)
    )
st.markdown("## 🛡️ Detection Engineering")

detect1, detect2 = st.columns(2)

with detect1:
    st.metric(
        "Alert Fatigue Score",
        f"{alert_fatigue_score:.1f}"
    )

with detect2:
    st.metric(
        "SOC Recommendation",
        soc_recommendation
    )

st.markdown("## 🧠 IOC Intelligence")

ioc1, ioc2 = st.columns(2)

with ioc1:
    st.code(
         [f"Port {p}" for p in sorted(ioc_ports)],
         language="text"
)

with ioc2:
    st.code(
        sorted(ioc_techniques),
        language="text"
)


# --------------------------------------------------
# SOC METRICS
# --------------------------------------------------
critical_alerts = 0
sqli_detected = 0
recon_events = 0
discovery_events = 0
high_severity_events = 0

ioc_techniques = set()
ioc_ports = set()
compromised_assets = set()

alert_fatigue_score = 0

lateral_movement_count = 0
defense_actions_count = 0


risk_score = 0
incident_priority = "LOW"
breach_detected = False
technique_counts = {
    "T1190": 0,
    "T1021": 0,
    "T1046": 0,
    "T1595": 0
}

# --------------------------------------------------
# MARL EVALUATION METRICS
# --------------------------------------------------

attack_attempts = 0
successful_attacks = 0

defense_actions = 0
successful_defenses = 0

attack_success_rate = 0
defense_effectiveness = 0


# --------------------------------------------------
# RUN SIMULATION
# --------------------------------------------------
if run_button:
    chart_placeholder = st.empty()
    timeline_placeholder = st.empty()

    total_reward = 0
    compromised_count = 0

    critical_alerts = 0
    sqli_detected = 0
    recon_events = 0
    discovery_events = 0
    high_severity_events = 0


    for step in range(env.max_steps):

        # ------------------------------------------
        # ATTACKER ACTION
        # ------------------------------------------
        action, _ = attacker.predict(
            obs,
            deterministic=False
        )
        previous_compromised = int(np.sum(obs))
        obs, reward, done, _ = env.step(action)
        current_compromised = int(np.sum(obs))
        compromised_count = current_compromised
        total_reward += reward

        # ------------------------------------------
        # DEFENDER ACTION
        # ------------------------------------------
        if not done:

            def_action, _ = defender.predict(
                obs,
                deterministic=False
            )

            obs, reward2, done, _ = env.step(def_action)

            total_reward += reward2

        # ------------------------------------------
        # NODE COLORS
        # ------------------------------------------
        colors = [
            "#ff3b30" if obs[i] == 1
            else "#34c759"
            for i in range(env.node_count)
        ]

        # ------------------------------------------
        # CREATE FIGURE
        # ------------------------------------------
        fig, ax = plt.subplots(figsize=(12, 7))

        fig.patch.set_facecolor("#f8fafc")
        ax.set_facecolor("#f8fafc")

        # ------------------------------------------
        # DRAW NODES
        # ------------------------------------------
        nx.draw_networkx_nodes(
            G,
            pos,
            node_color=colors,
            node_size=2600,
            edgecolors="black",
            linewidths=2,
            ax=ax
        )

        # ------------------------------------------
        # DRAW EDGES
        # ------------------------------------------
        nx.draw_networkx_edges(
            G,
            pos,
            edge_color="gray",
            width=2,
            ax=ax
        )

        # ------------------------------------------
        # DRAW LABELS
        # ------------------------------------------
        nx.draw_networkx_labels(
            G,
            pos,
            labels=labels,
            font_size=10,
            font_weight="bold",
            font_color="black",
            ax=ax
        )

        # ------------------------------------------
        # TITLE
        # ------------------------------------------
        ax.set_title(
            f"Cyber Attack Simulation — Step {step}",
            fontsize=26,
            color="black",
            fontweight="bold",
            pad=20
        )

        ax.axis("off")

        plt.tight_layout()

        # ------------------------------------------
        # SHOW GRAPH
        # ------------------------------------------
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

        # ------------------------------------------
        # METRICS
        # ------------------------------------------
        compromised_count = int(np.sum(obs))

        if compromised_count <= 1:
            threat_level = "LOW"

        elif compromised_count <= 3:
            threat_level = "MEDIUM"

        else:
            threat_level = "HIGH"

        if attack_attempts > 0:
            attack_success_rate = (
            successful_attacks / attack_attempts
            ) * 100
        else:
            attack_success_rate = 0

        if defense_actions > 0:
            defense_effectiveness = (
            successful_defenses / defense_actions
        ) * 100

        else:
            defense_effectiveness = 0

        reward_metric.metric(
            "Total Reward",
            round(total_reward, 2)
        )

        comp_metric.metric(
            "Compromised Nodes",
            compromised_count
        )

        step_metric.metric(
            "Simulation Step",
            step
        )

        threat_metric.metric(
            "Threat Level",
            threat_level
        )

        # ------------------------------------------
        # EVENT LOGS
        # ------------------------------------------
        timestamp = datetime.now().strftime("%H:%M:%S")

        # ==========================================
        # ATTACKER EVENT
        # ==========================================
        if action < env.node_count:
            attack_attempts += 1
            node_id = int(action)

            target_system = NODE_MAPPING.get(
            node_id,
            "Unknown"
            )

            vuln_info = VULNERABILITY_DB.get(
            target_system,
            {}
            )
            action_text = f"Attack Node {node_id}"

            attack_result = None

            # --------------------------------------
            # REAL SERVICE ATTACKS
            # --------------------------------------
            if node_id in real_ports:

                port = real_ports[node_id]

                # HTTP services
                if port in [5000, 8080]:

                    attack_result = probe_http_service(
                        port
                    )

                    # DVWA vulnerability testing
                    if (
                        port == 8080
                        and dvwa_logged_in
                    ):

                        sqli_result = (
                            test_basic_sqli()
                        )

                        if sqli_result.get(
                            "possible_sqli"
                        ):

                            attack_result[
                                "vulnerability"
                            ] = (
                                "SQL Injection Detected"
                            )

                # TCP services
                elif port == 3306:

                    attack_result = (
                        probe_tcp_service(port)
                    )
            # --------------------------------------
            # RESULT PARSING
            # --------------------------------------
            technique_id = "UNKNOWN"

            if attack_result:

                if current_compromised > previous_compromised:
                    successful_attacks += 1

                    if attack_result and "status_code" in attack_result:

                        action_text += (
                            f" | HTTP "
                            f"{attack_result['status_code']}"
                        )

                        ioc_ports.add(80)
                        ioc_techniques.add(technique_id)

                        if attack_result and "vulnerability" in attack_result:

                            action_text += (
                                f" | "
                                f"{attack_result['vulnerability']}"
                            )

                    elif attack_result and "port" in attack_result:

                        action_text += (
                            f" | Port "
                            f"{attack_result['port']} Open"
                        )

                        ioc_ports.add(
                             attack_result["port"]
                        )

                        ioc_techniques.add(
                            technique_id
                        )

                else:

                    action_text += (
                        " | Service Unreachable"
                    )
            detection_info = {}

            technique_id = vuln_info.get("mitre", "UNKNOWN")

            if technique_id in technique_counts:
                technique_counts[technique_id] += 1

            attack_name = ""

            if "SQL Injection" in action_text:
                attack_name = "SQL Injection"

            elif "Active Scanning" in action_text:
                attack_name = "Active Scanning"

            elif "Remote Services" in action_text:
                attack_name = "Remote Services"

            elif "Service Discovery" in action_text:
                attack_name = "Network Service Discovery"

            if attack_name:
                detection_info = DETECTION_RULES.get(
                attack_name,
                {}
            )

        # ==========================================
        # DEFENDER EVENT
        # ==========================================

        else:
            defense_actions += 1

            action_text = "Defender Action"

            if compromised_count > 0:
                random_node = np.random.randint(0, env.node_count)
                obs[random_node] = 0

                current_compromised = int(np.sum(obs))

            if current_compromised < previous_compromised:
                successful_defenses += 1

        # ------------------------------------------
        # MITRE ATT&CK MAPPING
        # ------------------------------------------
        mitre_data = map_attack_to_mitre(
            action_text
        )

        if mitre_data:

            action_text += (
                f" | "
                f"{mitre_data['technique']} "
                f"{mitre_data['name']} "
                f"[{mitre_data['tactic']}]"
            )
        # ------------------------------------------
        # THREAT LEVEL ANALYSIS
        # ------------------------------------------

        if "SQL Injection" in action_text:
            threat_level = ATTACK_SEVERITY.get(
                technique_id,
                "LOW"
            )

        if current_compromised >=3 and threat_level != "LOW":
            threat_level = "CRITICAL"

        # RISK SCORING

        risk_score = (
            (critical_alerts * 15)
            + (high_severity_events * 10)
            + (compromised_count * 12)
            + (successful_attacks * 8)
        )

        if risk_score >= 80:
            incident_priority = "P1"

        elif risk_score >= 50:
            incident_priority = "P2"

        elif risk_score >= 25:
            incident_priority = "P3"

        else:
            incident_priority = "P4"

        alert_fatigue_score = (
            len(event_logs) / (step + 1)
        ) * 10

        if compromised_count >= 5:
            breach_detected = True

        incident_status = "MONITORING"

        attacker_profile = "Script Kiddie"

        if risk_score >= 50:
            attacker_profile = "Organized Threat Actor"

        if risk_score >= 100:
            attacker_profile = "Advanced Persistent Threat"

        estimated_dwell_time = (
            compromised_count * 12
        )

        if risk_score >= 500:
            soc_recommendation = (
                "Initiate Enterprise Incident Response"
        )

        elif risk_score >= 300:
            soc_recommendation = (
            "Escalate To SOC Tier-2"
        )

        elif risk_score >= 150:
            soc_recommendation = (
                "Perform Threat Hunt"
        )

        else:
            soc_recommendation = (
                "Continue Monitoring"
        )

        if risk_score >= 80:
            incident_status = "ACTIVE INCIDENT"

        if compromised_count >= 5:
            incident_status = "BREACH CONFIRMED"


        # ------------------------------------------
        # KILL CHAIN MAPPING
        # ------------------------------------------
        kill_chain_stage = map_kill_chain(
            action_text
        )

        action_text += (
            f" | Stage: {kill_chain_stage}"
        )
        action_text += (
            f" | Threat: {threat_level}"
        )

        # ------------------------------------------
        # LIVE SOC COUNTERS
        # ------------------------------------------
        if threat_level == "CRITICAL":
            critical_alerts += 1

        if threat_level in ["HIGH", "CRITICAL"]:
            high_severity_events += 1

        if "SQL Injection" in action_text:
            sqli_detected += 1

        if "Active Scanning" in action_text:
            recon_events += 1

        if "Service Discovery" in action_text:
            discovery_events += 1

        if "Remote Services" in action_text:
            lateral_movement_count += 1

        # IOC COLLECTION

        ioc_techniques.add(technique_id)

        if attack_result and "port" in attack_result:
            ioc_ports.add(attack_result["port"])

        if current_compromised > previous_compromised:
            compromised_assets.add(node_id)

        # ALERT FATIGUE ESTIMATION

        if critical_alerts > 0:
            alert_fatigue_score = round(
                critical_alerts / max(step + 1, 1),
                2
        )


        # ------------------------------------------
        # FINAL LOG MESSAGE
        # ------------------------------------------
        compromised_count = int(np.sum(obs))
        explanation = explain_action(
            action,
            compromised_count,
            attack_result
        )
        log_message = (
            f"[{timestamp}] "
            f"{action_text} | "
            + (
                f"CVE: {vuln_info.get('cve', 'N/A')} | "
                f"CVSS: {vuln_info.get('cvss', 'N/A')} | "
            ) if action < env.node_count else ""
            + (
                f"ALERT: {detection_info.get('signature', 'N/A')} | "
                f"Severity: {detection_info.get('severity', 'N/A')} | "
                f"Confidence: {detection_info.get('confidence', 'N/A')}% | "
            ) if detection_info else ""
            + f"Reason: {explanation} | "
            + f"Compromised Nodes: "
            + f"{compromised_count}"
        )

        event_logs.insert(0, log_message)
        timeline_data.insert(0, {
            "Time": timestamp,
            "Stage": kill_chain_stage,
            "Threat": threat_level,
            "Event": action_text,
        })
        threat_history.append(
            critical_alerts
        )

        compromise_history.append(
            compromised_count
        )

        step_history.append(step)
        # ------------------------------------------
        # LIVE ANALYTICS CHARTS
        # ------------------------------------------
        with chart_placeholder.container():

            st.markdown("## 📈 Threat Analytics")

            chart_df = pd.DataFrame({
                "Step": step_history,
                "Critical Alerts": threat_history,
                "Compromised Nodes": compromise_history
            })

            st.line_chart(
                chart_df.set_index("Step"),
                use_container_width=True
            )
        # ------------------------------------------
        # SOC DASHBOARD METRICS
        # ------------------------------------------

        log_placeholder.text_area(
            "Live Threat Feed",
            "\n".join(event_logs[-12:]),
            height=260,
            disabled=True,
            key=f"soc_live_feed_{step}"
        )

# --------------------------------------------------
# SOC DASHBOARD METRICS
# --------------------------------------------------

soc1, soc2, soc3, soc4 = st.columns(4)

with soc1:
    st.metric("Critical Alerts", critical_alerts)

with soc2:
    st.metric("SQLi Events", sqli_detected)

with soc3:
    st.metric("Recon Events", recon_events)

with soc4:
    st.metric("Discovery Events", discovery_events)

soc5, soc6, soc7 = st.columns(3)

with soc5:
    st.metric("Risk Score", risk_score)

with soc6:
    st.metric("Incident Priority", incident_priority)

with soc7:
    st.metric("Incident Status", incident_status)

soc8, soc9, soc10 = st.columns(3)

with soc8:
    st.metric(
        "Attack Success %",
        f"{attack_success_rate:.1f}%"
    )
with soc9:
    st.metric(
        "Defense Effectiveness %",
        f"{defense_effectiveness:.1f}%"
    )

with soc10:
    st.metric(
        "Attacker Profile",
        attacker_profile
    )

soc11, soc12 = st.columns(2)

with soc11:
    st.metric(
        "Estimated Dwell Time",
        f"{estimated_dwell_time} mins"
    )

with soc12:
    st.metric(
        "High Severity",
        high_severity_events
    )

    # PERFORMANCE EVALUATION

    attack_success_rate = 0
    if attack_attempts > 0:
        attack_success_rate = (
            successful_attacks /
            attack_attempts
    ) * 100
    defense_success_rate = 0
    if defense_actions > 0:
        defense_success_rate = (
            successful_defenses /
            defense_actions
    ) * 100


        # ------------------------------------------
        # SPEED
        # ------------------------------------------
        time.sleep(speed)

# ------------------------------------------
# ATTACK TIMELINE
# ------------------------------------------

st.markdown("## 📊 Attack Timeline")

selected_threat = st.selectbox(
    "Filter Threat Level",
    ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    key="threat_filter"
)

if timeline_data:
    timeline_df = pd.DataFrame(timeline_data)

    threat_numeric = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    timeline_df["ThreatScore"] = (
        timeline_df["Threat"].map(threat_numeric)
    )

    if selected_threat != "ALL":
        timeline_df = timeline_df[
            timeline_df["Threat"] == selected_threat
        ]

    st.dataframe(
        timeline_df.head(25),
        use_container_width=True
    )

    fig_trend = px.line(
        timeline_df.head(25),
        x="Time",
        y="ThreatScore",
        color="Stage",
        title="Threat Escalation Trend"
    )
    st.plotly_chart(fig_trend, use_container_width=True)

    mitre_df = pd.DataFrame({
        "Technique": list(technique_counts.keys()),
        "Frequency": list(technique_counts.values())
    })

    st.markdown("## 🎯 MITRE ATT&CK Technique Frequency")
    st.dataframe(mitre_df, use_container_width=True)

    fig_mitre = px.pie(
        mitre_df,
        names="Technique",
        values="Frequency",
        title="MITRE ATT&CK Technique Distribution"
    )
    st.plotly_chart(fig_mitre, use_container_width=True)

    csv_data = timeline_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download SOC Report",
        data=csv_data,
        file_name="soc_attack_timeline.csv",
        mime="text/csv",
        key="download_soc_report"
    )

else:
    st.info("▶ Run the simulation to populate the Attack Timeline.")

# Incident Priority

if risk_score >= 150:
    incident_priority = "P1"
elif risk_score >= 100:
    incident_priority = "P2"
elif risk_score >= 50:
    incident_priority = "P3"
else:
    incident_priority = "LOW"


# Incident Status

incident_status = "MONITORING"

if risk_score >= 80:
    incident_status = "ACTIVE INCIDENT"

if compromised_count >= 5:
    incident_status = "BREACH CONFIRMED"

# SOC Recommendation + Threat Profiling

estimated_dwell_time = compromised_count * 12

if lateral_movement_count >= 3:
    attacker_profile = "Advanced Persistent Threat"
else:
    attacker_profile = "Opportunistic Attacker"

if incident_priority == "P1":
    soc_recommendation = "Initiate Enterprise Incident Response"
elif incident_priority == "P2":
    soc_recommendation = "Escalate To SOC Team"
else:
    soc_recommendation = "Monitoring"



st.success("Simulation Completed")

st.markdown("## 📋 Executive SOC Summary")

# Determine dominant technique safely
if technique_counts and any(technique_counts.values()):
    dominant_technique = max(
        technique_counts, key=technique_counts.get
    )
else:
    dominant_technique = technique_id  # "N/A" before sim runs

st.info(
    f"""
        Total Risk Score: {risk_score}

        Incident Priority: {incident_priority}

        Incident Status: {incident_status}

        Compromised Nodes: {compromised_count}

        Dominant Threat Technique: {technique_id}

        Estimated Dwell Time: {estimated_dwell_time} mins

        Attacker Profile: {attacker_profile}

        SOC Recommendation: {soc_recommendation}

     """
)
