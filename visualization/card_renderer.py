"""
visualization/card_renderer.py
------------------------------
Decouples responsive CSS-based Flexbox grids by mapping state metrics to components.
"""

from components.kpi_cards import render_kpi_cards

def render_metrics_cards(state: dict):
    """
    Extracts relevant KPI values from the canonical simulation state and
    invokes the responsive HTML/CSS renderer.
    """
    metrics = state["metrics"]
    
    render_kpi_cards(
        critical_alerts=metrics.get("critical_alerts", 0),
        sqli_detected=metrics.get("sqli_detected", 0),
        recon_events=metrics.get("recon_events", 0),
        discovery_events=metrics.get("discovery_events", 0),
        risk_score=metrics.get("risk_score", 0.0),
        incident_priority=metrics.get("incident_priority", "LOW"),
        incident_status=metrics.get("incident_status", "IDLE"),
        attack_success_rate=metrics.get("attack_success_rate", 0.0),
        defense_effectiveness=metrics.get("defense_effectiveness", 0.0),
        attacker_profile=metrics.get("attacker_profile", "Unknown"),
        estimated_dwell_time=metrics.get("estimated_dwell_time", 0),
        high_severity_events=metrics.get("high_severity_events", 0)
    )
