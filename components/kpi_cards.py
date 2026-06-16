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
    attacker_profile="Unknown",
    estimated_dwell_time=0,
    high_severity_events=0,
    # MARL KPIs
    isolation_actions=0,
    recovery_actions=0,
    block_actions=0,
    priority_actions=0,
    attacker_reward=0.0,
    defender_reward=0.0,
    nodes_recovered=0,
    nodes_isolated=0,
    nodes_blocked=0,
    show_header: bool = True
):

    if show_header:
        st.markdown("## Security Monitoring Console")

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
        {"title": "Isolation", "val": str(isolation_actions)},
        {"title": "Recovery", "val": str(recovery_actions)},
        {"title": "Blocked", "val": str(block_actions)},
        {"title": "Priority Ops", "val": str(priority_actions)},
        {"title": "Attacker Rwd", "val": f"{attacker_reward:.2f}"},
        {"title": "Defender Rwd", "val": f"{defender_reward:.2f}"},
        {"title": "Risk Score", "val": f"{risk_score}"},
        {"title": "Priority", "val": str(incident_priority)},
        {"title": "Status", "val": str(incident_status)},
        {"title": "Attack Success", "val": f"{attack_success_rate:.1f}%"},
        {"title": "Defense Eff.", "val": f"{defense_effectiveness:.1f}%"},
        {"title": "Nodes Recovered", "val": str(nodes_recovered)},
        {"title": "Nodes Isolated", "val": str(nodes_isolated)},
        {"title": "Nodes Blocked", "val": str(nodes_blocked)},
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
