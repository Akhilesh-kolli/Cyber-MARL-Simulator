import streamlit as st


def render_kpi_cards(
    critical_alerts,
    sqli_detected,
    recon_events,
    discovery_events,
    risk_score,
    incident_priority,
    incident_status,
    attack_success_rate,
    defense_effectiveness,
    attacker_profile,
    estimated_dwell_time,
    high_severity_events
):

    st.markdown("## 🚨 SOC Overview")

    soc1, soc2, soc3, soc4 = st.columns(4)

    with soc1:
        st.metric(
            "Critical Alerts",
            critical_alerts
        )

    with soc2:
        st.metric(
            "SQLi Events",
            sqli_detected
        )

    with soc3:
        st.metric(
            "Recon Events",
            recon_events
        )

    with soc4:
        st.metric(
            "Discovery Events",
            discovery_events
        )

    soc5, soc6, soc7 = st.columns(3)

    with soc5:
        st.metric(
            "Risk Score",
            risk_score
        )

    with soc6:
        st.metric(
            "Incident Priority",
            incident_priority
        )

    with soc7:
        st.metric(
            "Incident Status",
            incident_status
        )

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

        st.markdown(
            f"""
            <div style="
                background:#0f172a;
                padding:18px;
                border-radius:14px;
                border:1px solid #1e293b;
            ">

            <p style="
                color:#94a3b8;
                font-size:12px;
                margin-bottom:10px;
            ">
                Attacker Profile
            </p>

            <h2 style="
                color:white;
                margin:0;
            ">
                {attacker_profile}
            </h2>

            </div>
            """,
            unsafe_allow_html=True
        )

    soc11, soc12 = st.columns(2)

    with soc11:
        st.metric(
            "Estimated Dwell Time",
            f"{estimated_dwell_time} mins"
        )

    with soc12:
        st.metric(
            "High Severity Events",
            high_severity_events
        )
