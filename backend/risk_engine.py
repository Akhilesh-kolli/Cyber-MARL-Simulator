"""
backend/risk_engine.py
----------------------
Comprehensive cyber risk scoring, campaign level boundaries,
and sequential attacker progression state machine.
"""

import math
from utils.config import RISK_WEIGHTS, CVSS_RISK_MULTIPLIER
from utils.constants import STAGE_RANGES, ATTACK_SEVERITY

def calculate_risk_score(
    critical_alerts,
    high_severity_events,
    compromised_count,
    successful_attacks,
    events=None,
):
    """
    Compute composite risk score.
    Optionally uses CVSS scores from event dicts for higher accuracy.
    """
    base = (
        critical_alerts      * RISK_WEIGHTS["critical_alert"]
        + high_severity_events * RISK_WEIGHTS["high_severity"]
        + compromised_count    * RISK_WEIGHTS["compromised_node"]
        + successful_attacks   * RISK_WEIGHTS["successful_attack"]
    )

    # Add CVSS-weighted bonus if event data available
    cvss_bonus = 0.0
    if events:
        for e in events:
            cvss = e.get("cvss")
            if cvss and isinstance(cvss, (int, float)):
                if e.get("status") == "success":
                    cvss_bonus += cvss * CVSS_RISK_MULTIPLIER

    return int(base + cvss_bonus)


def get_incident_priority(risk_score):
    """P1 is highest severity."""
    if risk_score >= 150:
        return "P1"
    elif risk_score >= 100:
        return "P2"
    elif risk_score >= 50:
        return "P3"
    else:
        return "P4"


def get_incident_status(risk_score, compromised_count):
    if compromised_count >= 5:
        return "BREACH CONFIRMED"
    if risk_score >= 80:
        return "ACTIVE INCIDENT"
    return "MONITORING"


def get_threat_level(compromised_count, technique=None, cvss=None):
    """
    Multi-factor threat level.
    Uses node count as primary signal,
    CVSS and technique as secondary signals.
    """
    if compromised_count >= 4:
        return "CRITICAL"
    if compromised_count >= 3:
        # Escalate to CRITICAL if high CVSS
        if cvss and cvss >= 9.0:
            return "CRITICAL"
        return "HIGH"
    if compromised_count >= 2:
        return "MEDIUM"
    # Use technique severity for single-node events
    if technique and technique in ATTACK_SEVERITY:
        return ATTACK_SEVERITY[technique]
    return "LOW"


def get_attacker_profile(risk_score, lateral_movement_count):
    if lateral_movement_count >= 3 or risk_score >= 100:
        return "Advanced Persistent Threat"
    if risk_score >= 50:
        return "Organized Threat Actor"
    return "Script Kiddie"


def get_soc_recommendation(incident_priority):
    mapping = {
        "P1": "Initiate Enterprise Incident Response",
        "P2": "Escalate To SOC Tier-2",
        "P3": "Perform Threat Hunt",
        "P4": "Continue Monitoring",
    }
    return mapping.get(incident_priority, "Continue Monitoring")


def get_dwell_time(compromised_count):
    """Estimated dwell time in minutes."""
    return compromised_count * 12


def get_alert_fatigue_score(critical_alerts, step):
    if step <= 0:
        return 0.0
    return round(critical_alerts / max(step, 1), 2)


def get_attack_success_rate(successful_attacks, attack_attempts):
    if attack_attempts <= 0:
        return 0.0
    return round((successful_attacks / attack_attempts) * 100, 1)


def get_defense_effectiveness(successful_defenses, defense_actions):
    if defense_actions <= 0:
        return 0.0
    return round((successful_defenses / defense_actions) * 100, 1)


def get_dominant_technique(technique_counts):
    """Return the most frequent valid technique."""
    if not technique_counts or not any(technique_counts.values()):
        return "N/A"
    return max(technique_counts, key=technique_counts.get)


from analytics.bounded_metrics import (
    sigmoid_scale,
    clamp_0_95,
    boost_to_catastrophic,
    weighted_composite_score,
    entropy_scale,
)


def calculate_bounded_risk_score(
    nodes,
    lateral_movement_count,
    privilege_escalation_count,
    persistence_score,
    containment_failures,
    events,
    dwell_time,
    current_stage,
):
    """
    Multi-factor bounded risk scoring with dynamic soft caps mapping to campaign ranges.
    Uses normalized composite contributions and only permits catastrophic saturation
    when explicit enterprise compromise conditions are satisfied.
    """
    role_weights = {
        "DomainController": 5,
        "Database": 4,
        "Server": 3,
        "Firewall": 2,
        "Workstation": 2
    }

    compromised_weight = 0
    if isinstance(nodes, dict):
        for ninfo in nodes.values():
            if ninfo.get("status") in ("compromised", "contained"):
                role = ninfo.get("role", "Workstation")
                compromised_weight += role_weights.get(role, 2)
    elif isinstance(nodes, list):
        for ninfo in nodes:
            if ninfo.get("status") in ("compromised", "contained"):
                role = ninfo.get("role", "Workstation")
                compromised_weight += role_weights.get(role, 2)

    # Normalize counts by campaign scale to avoid runaway escalation
    total_events = len(events) if events else 0
    unique_techniques = len({str(e.get("technique", "")).upper() for e in events if e})
    event_scale = max(1, total_events)

    compromise_ratio = min(1.0, compromised_weight / 12.0)
    critical_ratio = min(1.0, (sum(1 for e in events if e.get("severity") == "CRITICAL") * 1.3) / max(6, event_scale))
    persistence_ratio = min(1.0, persistence_score / 18.0)
    exfiltration_ratio = min(1.0, (sum(1 for e in events if e.get("event_type") in ("Exfiltration", "Collection") or e.get("technique") in ("T1105", "T1486")) * 1.2) / max(5, event_scale))
    failed_defense_ratio = min(1.0, containment_failures / 5.0)
    anomaly_ratio = min(1.0, ((sum(1 for e in events if e.get("severity") in ("HIGH", "CRITICAL")) * 0.9) + unique_techniques * 0.2) / max(10, event_scale))

    # Compute component scores in [0,100]
    severity_score = critical_ratio * 100.0
    compromised_score = compromise_ratio * 100.0
    persistence_score_norm = persistence_ratio * 100.0
    exfiltration_score = exfiltration_ratio * 100.0
    anomaly_score = anomaly_ratio * 100.0

    # Estimate volatility from stage diversity using entropy
    stage_counts = {}
    for e in events or []:
        stg = e.get("kill_chain") or e.get("event_type") or "Unknown"
        stage_counts[stg] = stage_counts.get(stg, 0) + 1
    volatility_score = entropy_scale(stage_counts, max_val=60.0)

    # Weighted aggregation (raw weighted risk)
    weighted_risk = (
        (severity_score * 0.30)
        + (compromised_score * 0.25)
        + (persistence_score_norm * 0.15)
        + (exfiltration_score * 0.15)
        + (anomaly_score * 0.10)
        + (volatility_score * 0.05)
    )

    # Nonlinear sigmoid compression centered to slow growth after ~55
    try:
        compressed_risk = 100.0 / (1.0 + math.exp(-(weighted_risk - 65.0) / 12.0))
    except OverflowError:
        compressed_risk = 100.0

    # Damping above 85 to prevent rapid saturation
    if compressed_risk > 85.0:
        compressed_risk = 85.0 + ((compressed_risk - 85.0) * 0.35)

    # Catastrophic boost only when explicit conditions met
    catastrophic_conditions = {
        "wide_compromise": compromised_weight >= 14,
        "high_exfiltration": exfiltration_ratio >= 0.95,
        "active_persistence": persistence_ratio >= 0.9,
        "failed_containment": failed_defense_ratio >= 0.9,
        "low_stability": anomaly_ratio >= 0.9,
    }
    boosted = boost_to_catastrophic(compressed_risk, catastrophic_conditions)

    # Respect per-stage soft caps
    min_r, max_r = STAGE_RANGES.get(current_stage, (15, 95))
    # Map boosted risk into the stage range while preserving relative compression
    bounded_val = min_r + ((max(min(boosted, 95.0), 15.0) - 15.0) / 80.0) * (max_r - min_r)
    final = round(max(min_r, min(max_r, bounded_val)), 1)
    return final


def get_next_attack_stage(
    current_stage,
    step,
    compromised_count,
    logged_techniques,
    dc_compromised,
    db_or_srv_root,
    persistence_score,
):
    """
    Enforce sequential, stage-based campaign progression.
    Reconnaissance -> Discovery -> Initial Access -> Execution -> Credential Access -> Privilege Escalation -> Persistence -> Collection -> Exfiltration.
    """
    if not current_stage or current_stage == "Idle":
        return "Reconnaissance"

    if current_stage == "Recon":
        current_stage = "Reconnaissance"

    if current_stage == "Reconnaissance":
        if step > 1 or "T1046" in logged_techniques or "T1595" in logged_techniques:
            return "Discovery"
        return "Reconnaissance"

    if current_stage == "Discovery":
        if compromised_count >= 1 or "T1190" in logged_techniques or "T1078" in logged_techniques:
            return "Initial Access"
        return "Discovery"

    if current_stage == "Initial Access":
        if "T1059" in logged_techniques or compromised_count >= 2:
            return "Execution"
        return "Initial Access"

    if current_stage == "Execution":
        if "T1003" in logged_techniques or "T1078" in logged_techniques:
            return "Credential Access"
        if compromised_count >= 2:
            return "Privilege Escalation"
        return "Execution"

    if current_stage == "Credential Access":
        if "T1055" in logged_techniques or persistence_score >= 6:
            return "Privilege Escalation"
        return "Credential Access"

    if current_stage == "Privilege Escalation":
        if persistence_score >= 4 or compromised_count >= 4:
            return "Persistence"
        return "Privilege Escalation"

    if current_stage == "Persistence":
        if dc_compromised and step >= 15:
            return "Collection"
        return "Persistence"

    if current_stage == "Collection":
        if compromised_count >= 4 or "T1105" in logged_techniques:
            return "Exfiltration"
        return "Collection"

    if current_stage == "Exfiltration":
        return "Exfiltration"

    if current_stage == "Mitigation":
        return "Mitigation"

    return current_stage
