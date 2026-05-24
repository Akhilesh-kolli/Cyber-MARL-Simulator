"""
backend/telemetry_engine.py
--------------------------
Calculates and synchronizes all operational SOC telemetry, rates,
latencies, and attribution profiles. Derives strictly from canonical states.
"""

from utils.config import (
    RISK_WEIGHTS, CVSS_RISK_MULTIPLIER, DWELL_TIME_STEP_MULTIPLIER
)
from utils.constants import STAGE_RANGES

def update_telemetry_metrics(state: dict):
    """
    Updates the simulation_state["metrics"] partition.
    All variables are derived ONLY from canonical state objects:
    - state["nodes"]
    - state["events"]
    """
    events = state["events"]
    nodes = state["nodes"]
    metrics = state["metrics"]
    
    # Reset counts to derive strictly from canonical structures
    compromised_nodes = [nid for nid, ninfo in nodes.items() if ninfo["status"] in ("compromised", "contained")]
    compromised_count = len([nid for nid, ninfo in nodes.items() if ninfo["status"] == "compromised"])
    metrics["compromised_count"] = compromised_count
    
    # 1. Action Tallies from structured events
    attack_attempts = 0
    successful_attacks = 0
    defense_actions_count = 0
    successful_defenses = 0
    failed_defenses = 0
    
    recon_events = 0
    discovery_events = 0
    lateral_movement_count = 0
    sqli_detected = 0
    
    ioc_ports = set()
    ioc_techniques = set()
    compromised_assets = set()
    observed_attack_stages = set()
    technique_counts = {t: 0 for t in [
        "T1190", "T1021", "T1046", "T1059", "T1078", "T1003", "T1105",
        "T1562", "T1055", "T1547", "T1486", "T1110", "T1595"
    ]}
    
    alert_confidence_total = 0.0
    alert_count = 0
    critical_alerts = 0
    high_severity_events = 0
    
    for e in events:
        actor = e.get("actor")
        status = e.get("status")
        tech = e.get("technique")
        severity = e.get("severity")
        kill_chain = e.get("kill_chain") or ""
        tactic = e.get("tactic") or ""
        vuln = e.get("vulnerability") or ""
        port = e.get("port")
        service = e.get("service")
        tech_id = str(tech).strip().upper() if tech else ""
        
        # Ports
        if port and port not in ("N/A", ""):
            ioc_ports.add(str(port))
            
        # Severity
        if severity == "CRITICAL":
            critical_alerts += 1
        if severity in ("HIGH", "CRITICAL"):
            high_severity_events += 1

        # Attacker vs Defender tallies
        if actor == "attacker":
            attack_attempts += 1
            if status == "success":
                successful_attacks += 1
                if service and service != "SOC":
                    compromised_assets.add(service)
            
            # Techniques
            if tech_id and tech_id in technique_counts:
                technique_counts[tech_id] += 1
                ioc_techniques.add(tech_id)
            elif tech_id:
                technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
                ioc_techniques.add(tech_id)

            # Tactic counts
            if "recon" in kill_chain.lower() or "recon" in tactic.lower():
                recon_events += 1
            if "discovery" in kill_chain.lower() or "discovery" in tactic.lower():
                discovery_events += 1
            if "lateral" in kill_chain.lower() or "lateral" in tactic.lower():
                lateral_movement_count += 1
                
            sql_message = f"{str(vuln)} {str(e.get('message', ''))}".lower()
            if tech == "T1190" or any(keyword in sql_message for keyword in ["sql injection", "sqli", "sql payload", "sql query", "injection"]):
                sqli_detected += 1

            # Confidence
            conf = e.get("detection_confidence", 0)
            if conf:
                alert_confidence_total += conf
                alert_count += 1
                
        elif actor == "defender":
            defense_actions_count += 1
            if status == "success":
                successful_defenses += 1
            else:
                failed_defenses += 1
                
        if kill_chain and kill_chain != "Unknown":
            observed_attack_stages.add(kill_chain)

    metrics["attack_attempts"] = attack_attempts
    metrics["successful_attacks"] = successful_attacks
    metrics["defense_actions_count"] = defense_actions_count
    metrics["successful_defenses"] = successful_defenses
    metrics["failed_defenses"] = failed_defenses
    metrics["recon_events"] = recon_events
    metrics["discovery_events"] = discovery_events
    metrics["lateral_movement_count"] = lateral_movement_count
    metrics["sqli_detected"] = sqli_detected
    metrics["ioc_ports"] = ioc_ports
    metrics["ioc_techniques"] = ioc_techniques
    metrics["compromised_assets"] = compromised_assets
    metrics["observed_attack_stages"] = observed_attack_stages
    metrics["technique_counts"] = technique_counts
    metrics["critical_alerts"] = critical_alerts
    metrics["high_severity_events"] = high_severity_events
    
    # 2. Rate calculations
    metrics["attack_success_rate"] = round((successful_attacks / attack_attempts * 100.0), 1) if attack_attempts > 0 else 0.0
    metrics["defense_effectiveness"] = round((successful_defenses / defense_actions_count * 100.0), 1) if defense_actions_count > 0 else 0.0
    
    # 3. Fatigue Score & Confidence
    step = state["simulation"]["step"]
    fatigue_numerator = critical_alerts + (high_severity_events * 0.5) + (lateral_movement_count * 0.75)
    metrics["alert_fatigue_score"] = min(100.0, round(fatigue_numerator / max(step + 1, 1), 2))
    metrics["average_alert_confidence"] = min(100.0, round(alert_confidence_total / alert_count, 1)) if alert_count > 0 else 0.0
    
    # 4. Latencies & Dwell Time
    metrics["estimated_dwell_time"] = compromised_count * DWELL_TIME_STEP_MULTIPLIER
    
    # 5. Incident priorities & status
    risk_score = state["risk"].get("risk_score", 0.0)
    if compromised_count >= 5 or risk_score >= 90.0 or lateral_movement_count >= 5:
        metrics["incident_priority"] = "P1"
    elif compromised_count >= 3 or risk_score >= 70.0 or discovery_events >= 5:
        metrics["incident_priority"] = "P2"
    else:
        metrics["incident_priority"] = "LOW"
        
    if compromised_count >= 5 or (lateral_movement_count >= 4 and high_severity_events >= 10):
        metrics["incident_status"] = "BREACH CONFIRMED"
    elif risk_score >= 70.0 or compromised_count >= 3:
        metrics["incident_status"] = "ACTIVE INCIDENT"
    else:
        metrics["incident_status"] = "MONITORING"
        
    # 6. Attacker profiling & recommendations
    if compromised_count <= 1:
        metrics["attacker_profile"] = "Opportunistic Scanner"
    elif recon_events >= 5 and compromised_count <= 3:
        metrics["attacker_profile"] = "Reconnaissance Operator"
    elif lateral_movement_count >= 4 or metrics.get("persistence_score", 0) >= 12:
        metrics["attacker_profile"] = "Advanced Persistent Threat"
    elif discovery_events >= 6:
        metrics["attacker_profile"] = "Internal Network Explorer"
    else:
        metrics["attacker_profile"] = "Targeted Adversary"

    # Campaign Type
    diversity_score = min(100, len(ioc_techniques) * 6 + len(observed_attack_stages) * 10 + lateral_movement_count * 3)
    metrics["campaign_diversity_score"] = diversity_score
    
    if recon_events >= 6 and compromised_count <= 2:
        metrics["campaign_type"] = "Reconnaissance Campaign"
    elif lateral_movement_count >= 4 and compromised_count >= 3:
        metrics["campaign_type"] = "Lateral Expansion Campaign"
    elif metrics.get("persistence_score", 0) >= 12 and metrics.get("threat_correlation_score", 0) >= 40:
        metrics["campaign_type"] = "Persistent Intrusion Campaign"
    elif metrics.get("threat_momentum_score", 0) >= 60 and diversity_score >= 50:
        metrics["campaign_type"] = "Coordinated Multi-Stage Campaign"
    else:
        metrics["campaign_type"] = "General Intrusion Campaign"
        
    # Recommendation
    tactical_actions = []
    if compromised_count >= 1:
        tactical_actions.append("Isolate compromised node")
        tactical_actions.append("Quarantine affected host")
    if ioc_ports:
        tactical_actions.append("Block suspicious port access")
    if lateral_movement_count >= 1:
        tactical_actions.append("Contain lateral movement")
    if any("Domain" in asset or "Controller" in asset for asset in compromised_assets):
        tactical_actions.append("Disable compromised account")
    if not tactical_actions:
        tactical_actions.append("Maintain active hunt posture and enrich telemetry")

    executive_actions = []
    if metrics["incident_priority"] == "P1" or compromised_count >= 5:
        executive_actions = [
            "Activate incident response team",
            "Initiate enterprise escalation",
            "Notify leadership",
            "Invoke business continuity",
            "Assess operational impact"
        ]
    elif metrics["incident_priority"] == "P2" or critical_alerts >= 8:
        executive_actions = [
            "Escalate to senior SOC leadership",
            "Validate business-critical asset exposure",
            "Review executive incident posture",
            "Prepare leadership notification"
        ]
    else:
        executive_actions = [
            "Maintain senior operations awareness",
            "Continue monitoring and validate containment",
            "Review telemetry before executive briefing"
        ]

    metrics["tactical_recommendation"] = tactical_actions
    metrics["executive_response_strategy"] = executive_actions
    metrics["soc_recommendation"] = "; ".join(tactical_actions[:2])
    
    # Keep the deprecated/aliases key in metrics synced
    metrics["metrics"] = metrics
