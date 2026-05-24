"""
analytics/metrics_aggregator.py
-------------------------------
Master aggregator. Integrates telemetry metrics, bounds scores, and triggers
executive report generation.
"""

from backend.telemetry_engine import update_telemetry_metrics
from analytics.executive_analytics import generate_executive_report
from analytics.bounded_metrics import clamp_0_95

def aggregate_state_metrics(state: dict):
    """
    Orchestrates the entire metrics calculation and update cycle.
    Updates the canonical state dictionary in place.
    """
    # 1. Update basic telemetry
    update_telemetry_metrics(state)
    
    metrics = state["metrics"]
    
    # 2. Bound important analytic metrics using bounded transforms
    # Use clamp_0_95 to reserve 95-100 for explicit catastrophic conditions
    for key in [
        "anomaly_pressure_score",
        "threat_volatility_score",
        "containment_pressure_score",
        "threat_momentum_score",
        "threat_correlation_score",
        "persistence_score"
    ]:
        if key in metrics:
            try:
                val = float(metrics.get(key) or 0.0)
            except Exception:
                val = 0.0
            metrics[key] = round(clamp_0_95(val), 2)
            
    # 3. Generate executive report narrative elements
    generate_executive_report(state)
