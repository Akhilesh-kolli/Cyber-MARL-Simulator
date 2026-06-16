"""
analytics/hunt_analytics.py
---------------------------
Aggregates and formats all metrics relevant to the Threat Hunt console.
"""

def get_threat_hunt_summary(state: dict) -> dict:
    """
    Extracts and structures threat hunting metrics from the session state.
    """
    from analytics.ioc_engine import IOCEngine
    import pandas as pd

    metrics = state["metrics"]
    events = state.get("events", [])

    # Derive IOC registry from canonical events (authoritative)
    try:
        ioc_df = IOCEngine.generate_registry_df(events)
    except Exception:
        ioc_df = pd.DataFrame()

    # Technique counts and lists
    if ioc_df is not None and not ioc_df.empty and "Type" in ioc_df.columns:
        tech_rows = ioc_df[ioc_df["Type"].str.contains("Technique", na=False)]
        unique_techniques_count = int(tech_rows["IOC"].nunique()) if not tech_rows.empty else 0
        observed_techniques = sorted(list(tech_rows["IOC"].unique())) if not tech_rows.empty else []
        port_rows = ioc_df[ioc_df["Type"].str.contains("Port", na=False)] if "Type" in ioc_df.columns else pd.DataFrame()
        observed_ports_count = int(port_rows["IOC"].nunique()) if not port_rows.empty else 0
    else:
        unique_techniques_count = len(metrics.get("ioc_techniques", []))
        observed_techniques = sorted(list(metrics.get("ioc_techniques", [])))
        observed_ports_count = len(metrics.get("ioc_ports", []))

    # Tactical actions: prefer explicit defender_action events
    tactical_actions = []
    try:
        for e in events:
            if str(e.get("actor", "")).lower() == "defender":
                da = e.get("defender_action") or e.get("action")
                if da and da not in tactical_actions:
                    tactical_actions.append(da)
    except Exception:
        tactical_actions = metrics.get("tactical_recommendation", ["Awaiting Simulation"])

    return {
        "unique_techniques_count": unique_techniques_count,
        "observed_ports_count": observed_ports_count,
        "compromised_assets_count": metrics.get("compromised_count", 0),
        "alert_fatigue_score": metrics.get("alert_fatigue_score", 0.0),
        "successful_defenses": metrics.get("successful_defenses", 0),
        "failed_defenses": metrics.get("failed_defenses", 0),
        "observed_techniques": observed_techniques,
        "observed_stages": sorted(list(metrics.get("observed_attack_stages", []))),
        "tactical_actions": tactical_actions or metrics.get("tactical_recommendation", ["Awaiting Simulation"]),
    }
