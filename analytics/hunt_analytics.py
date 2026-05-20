"""
analytics/hunt_analytics.py
---------------------------
Aggregates and formats all metrics relevant to the Threat Hunt console.
"""

def get_threat_hunt_summary(state: dict) -> dict:
    """
    Extracts and structures threat hunting metrics from the session state.
    """
    metrics = state["metrics"]
    
    return {
        "unique_techniques_count": len(metrics.get("ioc_techniques", [])),
        "observed_ports_count": len(metrics.get("ioc_ports", [])),
        "compromised_assets_count": len(metrics.get("compromised_assets", [])),
        "alert_fatigue_score": metrics.get("alert_fatigue_score", 0.0),
        "successful_defenses": metrics.get("successful_defenses", 0),
        "failed_defenses": metrics.get("failed_defenses", 0),
        "observed_techniques": sorted(list(metrics.get("ioc_techniques", []))),
        "observed_stages": sorted(list(metrics.get("observed_attack_stages", []))),
        "soc_recommendation": metrics.get("soc_recommendation", "Awaiting Simulation"),
    }
