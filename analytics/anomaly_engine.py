"""
analytics/anomaly_engine.py
---------------------------
Bounded, realistic anomaly pressure and threat volatility calculations.
"""

from analytics.bounded_metrics import sigmoid_scale, entropy_scale, clamp_0_95

def update_anomaly_and_volatility(state: dict, threat_level: str):
    """
    Updates anomaly pressure and volatility using bounded, normalized calculations.
    """
    metrics = state["metrics"]
    
    # ── Anomaly Pressure: rolling weighted anomaly scoring with decay ────
    # Represents behavioral deviation intensity
    
    anomaly_base = (
        (len(metrics.get("ioc_ports", [])) * 0.8) +
        (len(metrics.get("ioc_techniques", [])) * 1.0) +
        (metrics.get("critical_alerts", 0) * 0.4) +
        (metrics.get("high_severity_events", 0) * 0.3)
    )
    
    # Threat level amplification
    threat_amplifier = 0.0
    if threat_level == "CRITICAL":
        threat_amplifier = 3.0
    elif threat_level == "HIGH":
        threat_amplifier = 1.5
    
    # Defense reduction
    defense_reduction = metrics.get("successful_defenses", 0) * 0.35
    
    # Compute raw anomaly score
    raw_anomaly = anomaly_base + threat_amplifier - defense_reduction
    
    # Normalize using sigmoid (smooth S-curve, max ~85)
    event_count = metrics.get("total_events", 1)
    midpoint = max(10, event_count * 0.3)
    metrics["anomaly_pressure_score"] = sigmoid_scale(
        raw_anomaly, 
        midpoint=midpoint, 
        steepness=0.04
    )
    metrics["anomaly_pressure_score"] = clamp_0_95(metrics["anomaly_pressure_score"])
    
    # ── Threat Volatility: entropy-based variability scoring ────
    # Represents unpredictability and tactical variation
    
    # Stage transition diversity
    stage_diversity = {
        "Reconnaissance": 1 if "Reconnaissance" in metrics.get("observed_attack_stages", []) else 0,
        "Discovery": 1 if "Discovery" in metrics.get("observed_attack_stages", []) else 0,
        "Initial Access": 1 if "Initial Access" in metrics.get("observed_attack_stages", []) else 0,
        "Execution": 1 if "Execution" in metrics.get("observed_attack_stages", []) else 0,
        "Persistence": 1 if "Persistence" in metrics.get("observed_attack_stages", []) else 0,
        "Lateral Movement": 1 if "Lateral Movement" in metrics.get("observed_attack_stages", []) else 0,
    }
    
    # Entropy-based variability from stage diversity
    entropy_component = entropy_scale(stage_diversity, max_val=40.0)
    
    # Severity variance component
    severity_variance = (
        (metrics.get("threat_momentum_score", 0) * 0.03) +
        (metrics.get("critical_alerts", 0) * 0.25) +
        (metrics.get("high_severity_events", 0) * 0.15) +
        (metrics.get("lateral_movement_count", 0) * 0.3)
    )
    
    # Defense effectiveness counterbalance
    defense_counter = metrics.get("successful_defenses", 0) * 0.3
    
    # Combine components with diminishing returns
    raw_volatility = entropy_component + severity_variance - defense_counter
    
    # Normalize with sigmoid
    volatility_midpoint = max(8, event_count * 0.25)
    metrics["threat_volatility_score"] = sigmoid_scale(
        raw_volatility,
        midpoint=volatility_midpoint,
        steepness=0.04
    )
    metrics["threat_volatility_score"] = clamp_0_95(metrics["threat_volatility_score"])

