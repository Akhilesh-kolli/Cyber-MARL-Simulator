"""
components/executive_panels.py
------------------------------
Renders the complete Executive SOC Summary workspace, dividing telemetry into five sub-panels.
"""

import streamlit as st
from analytics.mitre_mapper import get_dominant_technique

def _exec_card(title, body, border_color="#0ea5e9"):
    return (
        f'<div style="background:#0a1929;border-left:4px solid {border_color};'
        f'border-radius:10px;padding:14px 18px;margin-bottom:14px;'
        f'color:#cbd5e1;font-size:0.93rem;line-height:1.65;'
        f'word-break:break-word;white-space:normal;">'
        f'<span style="color:#93c5fd;font-weight:700;font-size:0.88rem;'
        f'letter-spacing:0.5px;text-transform:uppercase;">{title}</span><br/>'
        f'<span style="color:#e2e8f0;">{body}</span>'
        f'</div>'
    )

def render_executive_panel(state: dict):
    """
    Renders the Executive View workspace from pre-computed metrics and narratives in state.
    """
    st.markdown("## 📋 Executive SOC Summary")
    
    # Check if simulation started
    if not state.get("events") and not state.get("simulation", {}).get("running", False):
        st.info("▶ Run the simulation to generate the Executive SOC Summary.")
        return

    metrics = state["metrics"]
    exec_data = state["executive"]

    # -------------------------------------------------------
    # PANEL 1 — RISK OVERVIEW
    # -------------------------------------------------------
    st.markdown("### 🔴 Risk Overview")
    risk_c1, risk_c2, risk_c3, risk_c4 = st.columns(4)
    risk_c1.metric("Total Risk Score", metrics.get("risk_score", 0.0))
    risk_c2.metric("Incident Priority", metrics.get("incident_priority", "LOW"))
    risk_c3.metric("Incident Status", metrics.get("incident_status", "IDLE"))
    risk_c4.metric("Compromised Nodes", metrics.get("compromised_count", 0))

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------
    # PANEL 2 — THREAT METRICS
    # -------------------------------------------------------
    st.markdown("### 🎯 Threat Metrics")
    thr_c1, thr_c2, thr_c3, thr_c4 = st.columns(4)
    
    dominant_tech = get_dominant_technique(metrics.get("technique_counts", {}))
    thr_c1.metric("Dominant Technique", dominant_tech)
    thr_c2.metric("Estimated Dwell Time", f"{metrics.get('estimated_dwell_time', 0)} mins")
    thr_c3.metric("Detection Confidence", f"{metrics.get('average_alert_confidence', 0.0):.1f}%")
    thr_c4.metric("Campaign Diversity", exec_data.get("campaign_diversity_score", 0))

    thr_c5, thr_c6, thr_c7, thr_c8 = st.columns(4)
    thr_c5.metric("Threat Momentum", f"{metrics.get('threat_momentum_score', 0)}/100")
    thr_c6.metric("Threat Volatility", f"{metrics.get('threat_volatility_score', 0)}/100")
    thr_c7.metric("Anomaly Pressure", f"{metrics.get('anomaly_pressure_score', 0)}/100")
    thr_c8.metric("Containment Pressure", f"{metrics.get('containment_pressure_score', 0)}/100")

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------
    # PANEL 3 — SOC PERFORMANCE
    # -------------------------------------------------------
    st.markdown("### 🛡️ SOC Performance")
    soc_c1, soc_c2, soc_c3, soc_c4 = st.columns(4)
    soc_c1.metric("SOC Stability Index", f"{exec_data.get('soc_stability_index', 0.0):.1f}/100")
    soc_c2.metric("Threat Correlation", f"{metrics.get('threat_correlation_score', 0)}/100")
    soc_c3.metric("Research Consistency", f"{exec_data.get('research_consistency_score', 0.0):.1f}/100")
    soc_c4.metric("Research Confidence", f"{exec_data.get('research_confidence_index', 0.0):.1f}/100")

    st.markdown("#### 🔒 SOC Recommendation")
    soc_rec_color = "#ff3b30" if metrics.get("incident_priority") == "P1" else \
                    "#ff9500" if metrics.get("incident_priority") == "P2" else "#34c759"
    st.markdown(
        f'<div style="background:#0d1f36;border-left:5px solid {soc_rec_color};'
        f'border-radius:10px;padding:16px 20px;color:#e2e8f0;font-size:1.05rem;'
        f'font-weight:700;margin:10px 0 16px 0;word-break:break-word;white-space:normal;">'
        f'🔒 {metrics.get("soc_recommendation", "Awaiting Simulation")}'
        f'</div>',
        unsafe_allow_html=True
    )

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------
    # PANEL 4 — THREAT ACTOR PROFILE
    # -------------------------------------------------------
    st.markdown("### 👤 Threat Actor Profile")
    actor_c1, actor_c2, actor_c3, actor_c4 = st.columns(4)
    actor_c1.metric("Threat Actor Type", exec_data.get("threat_actor_type", "Opportunistic Threat Actor"))
    actor_c2.metric("Actor Confidence", f"{exec_data.get('threat_actor_confidence', 0)}%")
    actor_c3.metric("Attacker Profile", metrics.get("attacker_profile", "Unknown"))
    actor_c4.metric("Campaign Type", metrics.get("campaign_type", "Unknown Campaign"))

    act_c5, act_c6, act_c7, act_c8 = st.columns(4)
    act_c5.metric("Sophistication Score", f"{exec_data.get('threat_sophistication_score', 0)}/100")
    act_c6.metric("Actor Maturity", f"{exec_data.get('threat_actor_maturity', 0.0):.1f}/100")
    act_c7.metric("Business Impact", f"{exec_data.get('business_impact_score', 0.0):.1f}/100")
    act_c8.metric("Containment Urgency", f"{exec_data.get('containment_urgency', 0.0):.1f}/100")

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------
    # PANEL 5 — NARRATIVE INTELLIGENCE
    # -------------------------------------------------------
    st.markdown("### 📖 Narrative Intelligence")

    nar_left, nar_right = st.columns(2)
    with nar_left:
        st.markdown(
            _exec_card("Analyst Verdict", exec_data.get("analyst_verdict", "N/A"))
            + _exec_card("Campaign Classification", exec_data.get("campaign_classification", "N/A"), "#f59e0b")
            + _exec_card("Operational Discipline", exec_data.get("operational_discipline", "N/A"), "#a78bfa")
            + _exec_card("Incident Chronology", exec_data.get("incident_chronology", "N/A"), "#34d399"),
            unsafe_allow_html=True
        )
    with nar_right:
        st.markdown(
            _exec_card("Executive Impact", exec_data.get("executive_impact", "N/A"), "#ff3b30")
            + _exec_card("Response Priority", exec_data.get("response_priority", "N/A"), "#ff9500")
            + _exec_card("Attacker Intent", exec_data.get("attacker_intent", "N/A"), "#0ea5e9")
            + _exec_card("SOC Escalation Reasoning", exec_data.get("escalation_reason", "N/A"), "#f43f5e"),
            unsafe_allow_html=True
        )

    st.markdown("#### 📋 Executive Threat Briefing")
    st.markdown(
        _exec_card("Full Briefing", exec_data.get("executive_threat_briefing", "N/A"), "#0ea5e9"),
        unsafe_allow_html=True
    )

    with st.expander("📜 Extended Narrative Reports", key="exec_extended_narratives_expander"):
        st.markdown(
            _exec_card("Adversary Behavioral Narrative", exec_data.get("adversary_behavior", "N/A"), "#a78bfa")
            + _exec_card("Executive Decision Narrative", exec_data.get("executive_decision_narrative", "N/A"), "#f59e0b")
            + _exec_card("Campaign Progression Narrative", exec_data.get("campaign_progression", "N/A"), "#34d399")
            + _exec_card("SOC Investigation Narrative", exec_data.get("soc_investigation_narrative", "N/A"), "#0ea5e9")
            + _exec_card("Research Summary", exec_data.get("research_summary", "N/A"), "#94a3b8")
            + _exec_card("Simulation Reliability", exec_data.get("simulation_reliability", "N/A"), "#64748b"),
            unsafe_allow_html=True
        )
