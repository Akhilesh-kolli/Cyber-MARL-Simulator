# refactored dashboard.py

import time
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Cyber MARL SOC Platform",
    page_icon="🛡️",
    layout="wide"
)

# =====================================================
# CSS LOADER
# =====================================================


def load_css():
    css_path = Path("styles/theme.css")

    if css_path.exists():
        with open(css_path) as f:
            st.markdown(
                f"<style>{f.read()}</style>",
                unsafe_allow_html=True
            )


load_css()

# =====================================================
# DEFAULT STATE
# =====================================================

SIM_STATE = {
    "step": 0,
    "reward": 0.0,

    "risk_score": 0,
    "threat_level": "LOW",
    "incident_status": "NORMAL",

    "attack_success": 0,
    "defense_success": 100,
    "dwell_time": 0,

    "critical_alerts": 0,
    "sql_injection_attempts": 0,
    "recon_events": 0,
    "discovery_events": 0,

    "compromised_nodes": [],
    "compromised_count": 0,

    "threat_history": [],
    "attack_timeline": [],
    "event_log": [],

    "ioc_techniques": [],
    "ioc_ports": [],
    "compromised_assets": [],

    "mitre_mapping": {},

    "attack_stage": "Reconnaissance",

    "simulation_complete": False,

    "simulation_step": 0
}

# =====================================================
# SESSION INIT
# =====================================================

if "simulation_started" not in st.session_state:
    st.session_state.simulation_started = False

if "simulation_running" not in st.session_state:
    st.session_state.simulation_running = False

if "simulation_completed" not in st.session_state:
    st.session_state.simulation_completed = False

if "simulation_data" not in st.session_state:
    st.session_state.simulation_data = SIM_STATE.copy()

SIM_STATE = st.session_state.simulation_data

# =====================================================
# SIDEBAR
# =====================================================

with st.sidebar:

    st.markdown("## ⚙️ Simulation Controls")

    speed = st.slider(
        "Animation Speed",
        0.1,
        1.0,
        0.5,
        0.1
    )

    start_button = st.button(
        "▶ Start Simulation",
        use_container_width=True
    )

    reset_button = st.button(
        "🔄 Reset",
        use_container_width=True
    )

    st.markdown("---")

    workspace = st.radio(
        "SOC Workspace",
        [
            "Overview",
            "Threat Hunt",
            "IOC Intelligence",
            "MITRE Analytics",
            "Executive View"
        ]
    )

# =====================================================
# RESET LOGIC
# =====================================================

if reset_button:
    st.session_state.simulation_started = False
    st.session_state.simulation_running = False
    st.session_state.simulation_completed = False
    st.session_state.simulation_data = DEFAULT_SIM_STATE.copy()
    st.rerun()

# =====================================================
# START LOGIC
# =====================================================

if start_button:
    st.session_state.simulation_started = True
    st.session_state.simulation_running = True
    st.session_state.simulation_completed = False

# =====================================================
# HEADER
# =====================================================

left, right = st.columns([4, 2])

with left:

    if st.session_state.simulation_running:
        monitor_status = "🟢 LIVE MONITORING ACTIVE"
    elif st.session_state.simulation_completed:
        monitor_status = "🟠 SIMULATION COMPLETE"
    else:
        monitor_status = "⚪ STANDBY MODE"

    st.markdown(
        f"""
        <div class='glass-card'>
            <h2>🛡️ CYBER MARL SOC PLATFORM</h2>
            <h4>{monitor_status}</h4>
        </div>
        """,
        unsafe_allow_html=True
    )

with right:

    c1, c2, c3 = st.columns(3)

    c1.success("ATTACKER")
    c2.info("DEFENDER")
    c3.warning("ENGINE")

# =====================================================
# THREAT LEVEL ENGINE
# =====================================================


def calculate_threat_level(risk_score):

    if risk_score >= 1000:
        return "CRITICAL"

    elif risk_score >= 500:
        return "HIGH"

    elif risk_score >= 200:
        return "MEDIUM"

    return "LOW"


# =====================================================
# INCIDENT ENGINE
# =====================================================


def calculate_incident_status(risk_score, compromised_nodes):

    if compromised_nodes >= 5:
        return "BREACH CONFIRMED"

    elif risk_score >= 500:
        return "ACTIVE INCIDENT"

    elif risk_score >= 200:
        return "UNDER INVESTIGATION"

    return "NORMAL"


# =====================================================
# KPI SECTION
# =====================================================

risk_score = SIM_STATE["risk_score"]
compromised_nodes = SIM_STATE["compromised_count"]

SIM_STATE["threat_level"] = calculate_threat_level(risk_score)

SIM_STATE["incident_status"] = calculate_incident_status(
    risk_score,
    compromised_nodes
)

k1, k2, k3, k4 = st.columns(4)

with k1:

    active_threats = len(SIM_STATE["threat_history"])

    st.metric(
        "Active Threats",
        active_threats,
        delta="Idle Monitoring" if active_threats == 0 else "Threat Activity"
    )

with k2:

    st.metric(
        "Compromised Nodes",
        compromised_nodes,
        delta="No Compromise" if compromised_nodes == 0 else "Assets Breached"
    )

with k3:

    if st.session_state.simulation_running:
        defense_label = f"{SIM_STATE['defense_success']}%"
        defense_delta = "Defense Active"
    else:
        defense_label = "Standby"
        defense_delta = "Awaiting Simulation"

    st.metric(
        "Defense Success",
        defense_label,
        delta=defense_delta
    )

with k4:

    st.metric(
        "Incident Status",
        SIM_STATE["incident_status"],
        delta=f"Threat Level: {SIM_STATE['threat_level']}"
    )

# =====================================================
# OPERATIONAL BANNER
# =====================================================

if st.session_state.simulation_running:

    if SIM_STATE["incident_status"] == "BREACH CONFIRMED":
        banner_text = "☠️ BREACH CONFIRMED — CRITICAL RESPONSE ACTIVE"

    elif SIM_STATE["incident_status"] == "ACTIVE INCIDENT":
        banner_text = "🚨 ACTIVE INCIDENT — SOC ESCALATION IN PROGRESS"

    else:
        banner_text = "⚠️ THREAT ACTIVITY DETECTED"

elif st.session_state.simulation_completed:
    banner_text = "✅ SIMULATION COMPLETED"

else:
    banner_text = "⚪ SYSTEM READY — Awaiting Simulation Execution"

st.info(banner_text)

# =====================================================
# LIVE THREAT FEED
# =====================================================

st.markdown("## 📜 Live Threat Events")

feed_placeholder = st.empty()

# =====================================================
# THREAT HUNT
# =====================================================

if workspace == "Threat Hunt":

    st.markdown("## 🕵️ Threat Hunt Summary")

    h1, h2, h3 = st.columns(3)

    with h1:
        st.metric(
            "Unique Techniques",
            len(set(SIM_STATE["ioc_techniques"]))
        )

    with h2:
        st.metric(
            "Observed Ports",
            len(set(SIM_STATE["ioc_ports"]))
        )

    with h3:
        st.metric(
            "Compromised Assets",
            len(set(SIM_STATE["compromised_assets"]))
        )

# =====================================================
# IOC INTELLIGENCE
# =====================================================

if workspace == "IOC Intelligence":

    st.markdown("## 🧠 IOC Intelligence")

    left_ioc, right_ioc = st.columns(2)

    with left_ioc:

        ports = SIM_STATE["ioc_ports"]

        port_text = "\n".join(map(str, ports)) if ports else "No ports observed yet"

        st.text_area(
            "Observed Ports",
            port_text,
            height=150
        )

    with right_ioc:

        techs = SIM_STATE["ioc_techniques"]

        tech_text = "\n".join(techs) if techs else "No techniques observed yet"

        st.text_area(
            "MITRE Techniques",
            tech_text,
            height=150
        )

# =====================================================
# MITRE ANALYTICS
# =====================================================

if workspace == "MITRE Analytics":

    st.markdown("## 🎯 MITRE ATT&CK Analytics")

    techniques = SIM_STATE["ioc_techniques"]

    if techniques:

        freq = pd.Series(techniques).value_counts()

        st.dataframe(freq.reset_index())

        fig, ax = plt.subplots(figsize=(5, 5))

        fig.patch.set_facecolor("#081028")
        ax.set_facecolor("#081028")

        ax.pie(
            freq.values,
            labels=freq.index,
            autopct="%1.1f%%"
        )

        st.pyplot(fig)

    else:
        st.warning("No MITRE data available yet")

# =====================================================
# EXECUTIVE SUMMARY
# =====================================================

if workspace == "Executive View":

    st.markdown("## 📋 Executive SOC Summary")

    e1, e2, e3 = st.columns(3)

    e1.metric("Risk Score", SIM_STATE["risk_score"])
    e2.metric("Incident Priority", "P1" if risk_score >= 500 else "P3")
    e3.metric("Threat Level", SIM_STATE["threat_level"])

    e4, e5, e6 = st.columns(3)

    e4.metric("Attack Success %", SIM_STATE["attack_success"])
    e5.metric("Defense Success %", SIM_STATE["defense_success"])
    e6.metric("Dwell Time", f"{SIM_STATE['dwell_time']} mins")

# =====================================================
# OVERVIEW
# =====================================================

if workspace == "Overview":

    st.markdown("## 🌐 Real Infrastructure Status")

    s1, s2, s3 = st.columns(3)

    with s1:
        st.success("DVWA Vulnerable Web App : ONLINE")

    with s2:
        st.error("MySQL Database : OFFLINE")

    with s3:
        st.error("Nginx Internal Service : OFFLINE")

# =====================================================
# SIMULATION ENGINE
# =====================================================

if st.session_state.simulation_running:

    attack_stages = [
        "Discovery",
        "Initial Access",
        "Lateral Movement",
        "Persistence"
    ]

    techniques = [
        "T1190",
        "T1021",
        "T1046",
        "T1059"
    ]

    ports = [22, 80, 443, 8080]

    for step in range(1, 26):

        SIM_STATE["simulation_step"] = step

        SIM_STATE["reward"] -= 1.2

        if step % 4 == 0:

            SIM_STATE["compromised_count"] += 1
            SIM_STATE["risk_score"] += 250

            technique = techniques[step % len(techniques)]
            stage = attack_stages[step % len(attack_stages)]
            port = ports[step % len(ports)]

            SIM_STATE["ioc_techniques"].append(technique)
            SIM_STATE["ioc_ports"].append(port)
            SIM_STATE["compromised_assets"].append(f"Node-{step}")
            SIM_STATE["threat_history"].append(stage)

            SIM_STATE["attack_stage"] = stage

            event = (
                f"[STEP {step}] "
                f"{technique} detected | "
                f"Stage: {stage} | "
                f"Port: {port}"
            )

            SIM_STATE["event_log"].append(event)

        if len(SIM_STATE["event_log"]) > 10:
            SIM_STATE["event_log"] = SIM_STATE["event_log"][-10:]

        feed_placeholder.code(
            "\n".join(SIM_STATE["event_log"]),
            language="text"
        )

        time.sleep(speed)

    SIM_STATE["attack_success"] = 78
    SIM_STATE["defense_success"] = 41
    SIM_STATE["dwell_time"] = 60

    st.session_state.simulation_running = False
    st.session_state.simulation_completed = True

    st.success("Simulation Completed Successfully")

# =====================================================
# COMPLETED STATE
# =====================================================


if st.session_state.simulation_completed:

    st.download_button(
        label="📥 Download SOC Report",
        data=soc_report,
        file_name="soc_report.txt",
        mime="text/plain",
        use_container_width=True
    )
