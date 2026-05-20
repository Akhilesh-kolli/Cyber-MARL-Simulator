"""
analytics/anomaly_engine.py
---------------------------
Isolates calculations for anomaly pressure scores and threat volatility trends.
"""

def update_anomaly_and_volatility(state: dict, threat_level: str):
    """
    Updates the anomaly pressure and volatility scores inside state["metrics"].
    """
    metrics = state["metrics"]
    
    # 1. Anomaly Pressure Score Update
    if threat_level == "CRITICAL":
        metrics["anomaly_pressure_score"] += 4
    elif threat_level == "HIGH":
        metrics["anomaly_pressure_score"] += 2
        
    metrics["anomaly_pressure_score"] -= (
        metrics.get("successful_defenses", 0) * 0.12
    )
    metrics["anomaly_pressure_score"] = max(
        0, min(100, int(metrics["anomaly_pressure_score"]))
    )
    
    # 2. Threat Volatility Score Update
    metrics["threat_volatility_score"] += (
        (metrics.get("threat_momentum_score", 0) * 0.08)
        + (metrics.get("critical_alerts", 0) * 0.6)
        + (metrics.get("high_severity_events", 0) * 0.4)
        + (metrics.get("lateral_movement_count", 0) * 0.7)
    )
    metrics["threat_volatility_score"] -= (
        metrics.get("successful_defenses", 0) * 0.18
    )
    metrics["threat_volatility_score"] = max(
        0, min(100, int(metrics["threat_volatility_score"]))
    )
