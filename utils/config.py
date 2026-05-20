"""
utils/config.py
---------------
Dynamic configuration, soft caps, risk weights, scoring bounds, and alert fatigue thresholds.
"""

# Risk Engine weights
RISK_WEIGHTS = {
    "critical_alert": 15,
    "high_severity": 10,
    "compromised_node": 12,
    "successful_attack": 8,
}

CVSS_RISK_MULTIPLIER = 1.0

# Base parameters for risk sigmoid functions
RISK_SIGMOID_SCALE = 40.0

# Decay coefficients
ANOMALY_PRESSURE_DECAY = 0.12
THREAT_VOLATILITY_DECAY = 0.18
THREAT_MOMENTUM_DECAY = 0.35
THREAT_CORRELATION_DECAY = 0.25
PERSISTENCE_DECAY_DEF_ACTION = 0.05
PERSISTENCE_DECAY_SUCCESSFUL_DEF = 0.12

# Detection confidence base levels
BASE_ALERT_CONFIDENCE = 45
MAX_ALERT_CONFIDENCE = 100
MIN_ALERT_CONFIDENCE = 25

# Performance Telemetry Latency multipliers
DWELL_TIME_STEP_MULTIPLIER = 12
