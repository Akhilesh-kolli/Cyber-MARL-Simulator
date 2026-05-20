"""
risk_engine.py
--------------
All risk scoring, incident priority, dwell time,
attacker profiling, and SOC recommendation logic.

Reads from structured event dicts — no string parsing.
"""

# --------------------------------------------------
# RISK WEIGHTS
# --------------------------------------------------
RISK_WEIGHTS = {
    "critical_alert":    15,
    "high_severity":     10,
    "compromised_node":  12,
    "successful_attack":  8,
}

# CVSS contributes directly to risk when available
CVSS_RISK_MULTIPLIER = 1


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
    cvss_bonus = 0
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
    from event_engine import ATTACK_SEVERITY
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


STAGE_RANGES = {
    "Recon": (20, 45),
    "Reconnaissance": (20, 45),
    "Discovery": (20, 45),
    "Initial Access": (45, 70),
    "Lateral Movement": (70, 90),
    "Privilege Escalation": (70, 90),
    "Persistence": (70, 90),
    "Exfiltration": (90, 100),
    "Idle": (0, 20),
}


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
    """
    role_weights = {
        "DomainController": 5,
        "Database": 4,
        "Server": 3,
        "Firewall": 2,
        "Workstation": 2
    }

    node_score = 0
    if isinstance(nodes, dict):
        for ninfo in nodes.values():
            if ninfo.get("status") in ("compromised", "contained"):
                role = ninfo.get("role", "Workstation")
                node_score += role_weights.get(role, 2)
    elif isinstance(nodes, list):
        for ninfo in nodes:
            if ninfo.get("status") in ("compromised", "contained"):
                role = ninfo.get("role", "Workstation")
                node_score += role_weights.get(role, 2)

    cvss_sum = 0
    if events:
        for e in events:
            if e.get("status") == "success":
                cvss = e.get("cvss")
                if cvss and isinstance(cvss, (int, float)):
                    cvss_sum += cvss

    raw_score = (
        node_score * 8
        + lateral_movement_count * 5
        + privilege_escalation_count * 8
        + persistence_score * 3
        + containment_failures * 6
        + cvss_sum * 1.5
        + dwell_time * 0.5
    )

    import math
    if raw_score <= 0:
        val = 0.0
    else:
        val = 100.0 / (1.0 + math.exp(-raw_score / 40.0))

    min_r, max_r = STAGE_RANGES.get(current_stage, (20, 100))
    bounded_val = min_r + (val / 100.0) * (max_r - min_r)
    return round(bounded_val, 1)


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
    Enforce sequential, step-by-step campaign stage progression.
    Reconnaissance -> Discovery -> Initial Access -> Lateral Movement -> Privilege Escalation -> Persistence -> Exfiltration.
    """
    if not current_stage or current_stage == "Idle":
        return "Reconnaissance"

    # Normalize name to full form
    if current_stage == "Recon":
        current_stage = "Reconnaissance"

    if current_stage == "Reconnaissance":
        if step > 0 or "T1046" in logged_techniques or "T1595" in logged_techniques:
            return "Discovery"
        return "Reconnaissance"

    if current_stage == "Discovery":
        if compromised_count >= 1:
            return "Initial Access"
        return "Discovery"

    if current_stage == "Initial Access":
        if compromised_count >= 2:
            return "Lateral Movement"
        return "Initial Access"

    if current_stage == "Lateral Movement":
        if db_or_srv_root or compromised_count >= 3:
            return "Privilege Escalation"
        return "Lateral Movement"

    if current_stage == "Privilege Escalation":
        if persistence_score >= 4 or compromised_count >= 4:
            return "Persistence"
        return "Privilege Escalation"

    if current_stage == "Persistence":
        if dc_compromised and step >= 15:
            return "Exfiltration"
        return "Persistence"

    return current_stage
