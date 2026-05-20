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

    # Shorten profile name if too long
    profile_short = attacker_profile
    if attacker_profile == "Advanced Persistent Threat":
        profile_short = "APT"
    elif attacker_profile == "Organized Threat Actor":
        profile_short = "Organized"
    elif attacker_profile == "Script Kiddie":
        profile_short = "Script Kid"

    # Clean, shortened labels
    metrics = [
        {"title": "Critical Alerts", "val": str(critical_alerts)},
        {"title": "SQLi Events", "val": str(sqli_detected)},
        {"title": "Recon", "val": str(recon_events)},
        {"title": "Discovery", "val": str(discovery_events)},
        {"title": "Risk Score", "val": f"{risk_score}"},
        {"title": "Priority", "val": str(incident_priority)},
        {"title": "Status", "val": str(incident_status)},
        {"title": "Attack Success", "val": f"{attack_success_rate:.1f}%"},
        {"title": "Defense Eff.", "val": f"{defense_effectiveness:.1f}%"},
        {"title": "Profile", "val": profile_short},
        {"title": "Dwell Time", "val": f"{estimated_dwell_time}m"},
        {"title": "High Severity", "val": str(high_severity_events)},
    ]

    cards_html = ""
    for m in metrics:
        cards_html += f"""
        <div class="kpi-flex-card">
            <div class="kpi-card-title">{m['title']}</div>
            <div class="kpi-card-value">{m['val']}</div>
        </div>
        """

    st.markdown(
        f"""
        <div class="kpi-flex-grid">
            {cards_html}
        </div>
        """,
        unsafe_allow_html=True
    )
