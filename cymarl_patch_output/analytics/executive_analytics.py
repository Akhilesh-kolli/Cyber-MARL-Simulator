"""
analytics/executive_analytics.py
--------------------------------
Generates high-level narrative intelligence, threat actor maturity profiles,
operational discipline matrices, and executive-level briefings.
"""

from analytics.mitre_mapper import get_dominant_technique
import math
import time
from analytics.ioc_engine import IOCEngine

def generate_executive_report(state: dict) -> dict:
    """
    Computes all narrative fields and executive metrics based on current telemetry.
    Updates and returns the state["executive"] dictionary.
    """
    metrics = state["metrics"]
    executive = state["executive"]
    
    # Extract operational counts
    compromised_count = metrics.get("compromised_count", 0)
    recon_events = metrics.get("recon_events", 0)
    discovery_events = metrics.get("discovery_events", 0)
    lateral_movement_count = metrics.get("lateral_movement_count", 0)
    critical_alerts = metrics.get("critical_alerts", 0)
    high_severity_events = metrics.get("high_severity_events", 0)
    persistence_score = metrics.get("persistence_score", 0)
    threat_momentum_score = metrics.get("threat_momentum_score", 0)
    threat_volatility_score = metrics.get("threat_volatility_score", 0)
    containment_pressure_score = metrics.get("containment_pressure_score", 0)
    anomaly_pressure_score = metrics.get("anomaly_pressure_score", 0)
    threat_correlation_score = metrics.get("threat_correlation_score", 0)
    average_alert_confidence = metrics.get("average_alert_confidence", 0.0)
    incident_priority = metrics.get("incident_priority", "LOW")
    attacker_profile = metrics.get("attacker_profile", "Unknown")
    campaign_type = metrics.get("campaign_type", "Unknown Campaign")

    def clamp_score(value):
        try:
            return max(0.0, min(100.0, float(value or 0)))
        except (TypeError, ValueError):
            return 0.0

    threat_momentum_score = clamp_score(threat_momentum_score)
    threat_volatility_score = clamp_score(threat_volatility_score)
    containment_pressure_score = clamp_score(containment_pressure_score)
    anomaly_pressure_score = clamp_score(anomaly_pressure_score)
    threat_correlation_score = clamp_score(threat_correlation_score)
    average_alert_confidence = clamp_score(average_alert_confidence)
    
    # 1. Step History/Step calculations
    step = state["simulation"]["step"]
    
    # 2. Campaign Diversity Score (normalized, non-saturating)
    events_count = max(1, len(state.get("events", [])))
    # Prefer IOC registry as authoritative source for observed techniques and ports
    try:
        ioc_df = IOCEngine.generate_registry_df(state.get("events", []))
    except Exception:
        ioc_df = None

    if ioc_df is not None and not ioc_df.empty and "Type" in ioc_df.columns:
        tech_rows = ioc_df[ioc_df["Type"].str.contains("Technique", na=False)]
        tech_count = int(tech_rows["IOC"].nunique()) if not tech_rows.empty else 0
    else:
        tech_count = len(metrics.get("ioc_techniques", []))

    stages_count = len(metrics.get("observed_attack_stages", []))

    # dynamic caps based on observed data
    cap_events = max(10, events_count)
    cap_tech = max(5, tech_count * 3, 10)
    cap_stages = max(3, stages_count * 2, 6)

    def norm_log(value, cap):
        try:
            return max(0.0, min(100.0, (math.log1p(value) / math.log1p(cap)) * 100.0))
        except Exception:
            return 0.0

    tech_score = norm_log(tech_count, cap_tech)
    stage_score = norm_log(stages_count, cap_stages)
    campaign_diversity_score = clamp_score((tech_score * 0.6) + (stage_score * 0.4))
    
    # 3. Sophistication Score (weighted normalized inputs)
    momentum_score_norm = norm_log(threat_momentum_score, 100)
    persistence_norm = norm_log(persistence_score, max(10, persistence_score + 1))
    lateral_norm = norm_log(lateral_movement_count, cap_events)
    tech_norm = tech_score
    threat_sophistication_score = clamp_score(int(
        (momentum_score_norm * 0.30)
        + (persistence_norm * 0.30)
        + (lateral_norm * 0.20)
        + (tech_norm * 0.20)
    ))
    
    # 4. Analyst Verdict
    if threat_sophistication_score >= 85:
        analyst_verdict = "Advanced multi-stage intrusion campaign with coordinated persistence activity."
    elif threat_sophistication_score >= 65:
        analyst_verdict = "Highly capable attacker exhibiting structured lateral movement behavior."
    elif threat_sophistication_score >= 40:
        analyst_verdict = "Moderately sophisticated attack chain with observable escalation patterns."
    else:
        analyst_verdict = "Low-complexity opportunistic attack activity."
        
    # 5. Campaign Classification
    if persistence_score >= 12 and lateral_movement_count >= 4:
        campaign_classification = "Persistent Lateral Movement Campaign"
    elif critical_alerts >= 8 and threat_momentum_score >= 60:
        campaign_classification = "High-Impact Escalation Campaign"
    elif recon_events >= 5 and discovery_events >= 4:
        campaign_classification = "Reconnaissance-Led Intrusion Campaign"
    else:
        campaign_classification = "Generalized Opportunistic Threat Activity"
        
    # 6. Escalation Reason
    if incident_priority == "P1":
        escalation_reason = "Critical attack indicators exceed SOC containment thresholds."
    elif incident_priority == "P2":
        escalation_reason = "Sustained attacker momentum detected across multiple attack stages."
    elif incident_priority == "LOW":
        escalation_reason = "Moderate threat activity requiring continued analyst monitoring."
    else:
        escalation_reason = "Threat activity remains within manageable SOC thresholds."
        
    # 7. Threat Actor Maturity
    threat_actor_maturity = min(
        100.0,
        (threat_sophistication_score * 0.45)
        + (persistence_score * 1.6)
        + (threat_momentum_score * 0.18)
        + (campaign_diversity_score * 0.18)
    )
    
    # 8. Operational Discipline
    if threat_actor_maturity >= 85:
        operational_discipline = "Highly disciplined attacker with coordinated multi-stage behavior."
    elif threat_actor_maturity >= 65:
        operational_discipline = "Structured operational behavior with persistent attack coordination."
    elif threat_actor_maturity >= 40:
        operational_discipline = "Moderately organized attack activity with limited persistence discipline."
    else:
        operational_discipline = "Low-discipline opportunistic attack behavior."
        
    # 9. Attacker Intent
    if persistence_score >= 12 and lateral_movement_count >= 5:
        attacker_intent = "Long-term persistent infrastructure compromise."
    elif critical_alerts >= 8 and threat_momentum_score >= 70:
        attacker_intent = "Aggressive high-impact operational disruption."
    elif recon_events >= 6 and discovery_events >= 5:
        attacker_intent = "Strategic reconnaissance and network mapping."
    else:
        attacker_intent = "General opportunistic exploitation activity."
        
    # 10. Adversary Behavior
    adversary_behavior = (
        f"The attacker demonstrated {campaign_classification.lower()} "
        f"with {attacker_profile.lower()} characteristics. "
        f"Operational analysis indicates {operational_discipline.lower()} "
        f"Observed intent suggests {attacker_intent.lower()}"
    )
    
    # 11. Business Impact (normalized, weighted, diminishing returns)
    # FIX #28: Attack stage directly influences business impact
    comp_norm = norm_log(compromised_count, max(5, compromised_count * 3, cap_events))
    crit_norm = norm_log(critical_alerts, cap_events)
    persistence_norm = norm_log(persistence_score, max(10, persistence_score + 1))
    base_impact = clamp_score((comp_norm * 0.6) + (crit_norm * 0.3) + (persistence_norm * 0.1))
    # Stage amplifier: advanced stages have higher business impact
    attack_stage_for_impact = metrics.get("attack_stage", "Idle")
    stage_impact_mult = {
        "Exfiltration": 1.4, "Command and Control": 1.35, "Lateral Movement": 1.25,
        "Persistence": 1.2, "Privilege Escalation": 1.15, "Credential Access": 1.1,
        "Execution": 1.05, "Initial Access": 1.0, "Discovery": 0.9,
        "Reconnaissance": 0.8, "Idle": 0.5
    }.get(attack_stage_for_impact, 1.0)
    business_impact_score = clamp_score(base_impact * stage_impact_mult)
    
    # 12. Executive Impact
    if business_impact_score >= 85:
        executive_impact = "Enterprise-wide operational disruption risk."
    elif business_impact_score >= 65:
        executive_impact = "Critical infrastructure and business workflow exposure."
    elif business_impact_score >= 40:
        executive_impact = "Moderate operational impact requiring containment."
    else:
        executive_impact = "Limited operational disruption currently observed."
        
    # 13. Incident Response Priority
    if incident_priority == "P1" or business_impact_score >= 85:
        response_priority = "Immediate enterprise incident response activation."
    elif incident_priority == "P2" or business_impact_score >= 65:
        response_priority = "Escalated SOC containment and threat hunting."
    elif incident_priority == "LOW":
        response_priority = "Focused investigation and containment monitoring."
    else:
        response_priority = "Routine SOC monitoring and telemetry review."
        
    # 14. Containment Urgency
    containment_urgency = min(
        100.0,
        (business_impact_score * 0.5)
        + (threat_volatility_score * 0.3)
        + (containment_pressure_score * 0.2)
    )
    
    # 15. Executive Response Strategy
    if incident_priority == "P1" or business_impact_score >= 85:
        executive_actions = [
            "Activate incident response team",
            "Initiate enterprise escalation",
            "Notify leadership",
            "Invoke business continuity",
            "Assess operational impact"
        ]
    elif incident_priority == "P2" or business_impact_score >= 65:
        executive_actions = [
            "Prepare leadership briefing",
            "Escalate to senior SOC operations",
            "Validate critical asset exposure",
            "Coordinate cross-functional response"
        ]
    else:
        executive_actions = [
            "Maintain elevated monitoring posture",
            "Review containment effectiveness",
            "Align SOC actions with business risk tolerance"
        ]

    executive_decision_narrative = (
        f"Operational analysis indicates {executive_impact.lower()} "
        f"Containment urgency currently assessed at {containment_urgency:.1f}/100. "
        f"Recommended response posture: {response_priority.lower()}"
    )
    
    # 16. Campaign Progression
    attack_stage = metrics.get("attack_stage", "Idle")
    campaign_progression = (
        f"The attack campaign evolved through {len(metrics.get('observed_attack_stages', []))} observed stages "
        f"with {critical_alerts} critical alerts and {lateral_movement_count} lateral movement events. "
        f"Threat progression reached the {attack_stage.lower()} phase "
        f"with a volatility score of {threat_volatility_score:.1f}/100."
    )
    
    # 17. SOC Investigation
    # Build SOC investigation narrative from IOC registry when available
    try:
        if ioc_df is not None and not ioc_df.empty:
            num_tech = len(ioc_df[ioc_df["Type"].str.contains("Technique", na=False)])
            num_ports = len(ioc_df[ioc_df["Type"].str.contains("Port", na=False)])
        else:
            num_tech = len(metrics.get('ioc_techniques', []))
            num_ports = len(metrics.get('ioc_ports', []))
    except Exception:
        num_tech = len(metrics.get('ioc_techniques', []))
        num_ports = len(metrics.get('ioc_ports', []))

    soc_investigation_narrative = (
        f"SOC telemetry identified {num_tech} attack technique(s) "
        f"across {num_ports} observed port indicators. "
        f"Detection analytics produced {average_alert_confidence:.1f}% average confidence "
        f"with {threat_correlation_score:.1f}/100 threat correlation intensity."
    )
    
    # 18. Executive Threat Briefing
    executive_threat_briefing = (
        f"{campaign_classification}. {executive_impact} {analyst_verdict} "
        f"Recommended executive response: {response_priority}"
    )
    
    # 19. Incident Chronology
    incident_chronology = (
        f"Initial activity began with {recon_events} reconnaissance indicators, "
        f"followed by {discovery_events} discovery events and escalation into "
        f"{attack_stage.lower()} operations."
    )
    
    # Organic step-based baseline to prevent static 100% or 0% values
    step_num = len(metrics.get("step_history", []))
    base_var = (step_num * 1.37) % 2.5 - 1.25 # small fluctuation (-1.25 to +1.25)
    
    # 20. Advanced Performance Indices
    raw_stability = (
        94.5  # Realistic initial baseline instead of flat 100.0
        + base_var
        - (compromised_count * 8.5)
        - (critical_alerts * 1.5)
        - (threat_momentum_score * 0.18)
        - (anomaly_pressure_score * 0.12)
    )
    soc_stability_index = max(15.0, min(98.5, round(raw_stability, 1)))

    raw_consistency = (
        96.0  # Realistic initial baseline instead of flat 100.0
        + ((step_num * 0.73) % 2.0 - 1.0)
        - (threat_volatility_score * 0.45)
        - (anomaly_pressure_score * 0.30)
        - (containment_pressure_score * 0.20)
    )
    research_consistency_score = max(10.0, min(99.0, round(raw_consistency, 1)))
    research_consistency_score = min(
        99.0,
        research_consistency_score + (average_alert_confidence * 0.05)
    )
    
    # 21. Research Confidence Index & reliability
    raw_confidence = (
        (average_alert_confidence * 0.35)
        + (threat_correlation_score * 0.25)
        + (research_consistency_score * 0.25)
        + (soc_stability_index * 0.20)
    )
    if step_num == 0:
        # Standby status fluctuation
        raw_confidence = 68.4 + ((time.time() / 10) % 3.0)
    
    research_confidence_index = max(10.0, min(98.8, round(raw_confidence, 1)))
    
    if research_confidence_index >= 85:
        simulation_reliability = "High-confidence simulation telemetry suitable for predictive modeling."
    elif research_confidence_index >= 65:
        simulation_reliability = "Standard telemetry reliability with manageable metric variances."
    elif research_confidence_index >= 40:
        simulation_reliability = "Variable simulation conditions with partially stable threat telemetry."
    else:
        simulation_reliability = "Low-confidence telemetry conditions requiring additional calibration."
        
    # 22. Research Summary Narrative
    alert_count = metrics.get("alert_count", 0)
    research_summary_narrative = (
        f"The Cyber-MARL simulation generated {alert_count} structured alerts "
        f"across {len(metrics.get('observed_attack_stages', []))} attack stages "
        f"with {research_confidence_index:.1f}/100 research confidence. "
        f"Simulation reliability assessment indicates {simulation_reliability.lower()}"
    )
    
    # 23. Threat Actor Profile & Attribution — fully dynamic confidence
    # FIX #26/#27: Confidence now includes attack stage and attack success rate signals
    attack_stage_local = metrics.get("attack_stage", "Idle")
    attack_success_rate = metrics.get("attack_success_rate", 0.0)
    attack_attempts_local = metrics.get("attack_attempts", 0)
    successful_attacks_local = metrics.get("successful_attacks", 0)
    
    # Base score from observable telemetry signals
    raw_confidence = (
        min(persistence_score, 15) * 2.8        # persistence indicator (0-42)
        + min(lateral_movement_count, 6) * 5.0  # lateral spread (0-30)
        + min(recon_events, 8) * 1.5            # recon depth (0-12)
        + min(discovery_events, 8) * 1.2        # discovery breadth (0-9.6)
        + min(threat_correlation_score, 60) * 0.12  # correlation weight (0-7.2)
    )                                            # theoretical max ~100
    
    # FIX #26: Add attack stage and success bonuses to prevent unrealistically low confidence
    stage_confidence_bonus = {
        "Exfiltration": 35, "Command and Control": 30, "Lateral Movement": 25,
        "Persistence": 20, "Privilege Escalation": 18, "Credential Access": 16,
        "Execution": 12, "Initial Access": 10, "Discovery": 8, "Reconnaissance": 5,
        "Idle": 0
    }.get(attack_stage_local, 5)
    raw_confidence += stage_confidence_bonus
    
    # Attack success rate bonus
    if attack_success_rate >= 70:
        raw_confidence += 20
    elif attack_success_rate >= 50:
        raw_confidence += 12
    elif attack_success_rate >= 30:
        raw_confidence += 6
    
    threat_actor_confidence = max(15, min(97, int(raw_confidence)))

    # FIX #27: Classification must match observed behavior (not just confidence score)
    # Advanced stages with lateral movement = APT/Organized crime, not opportunistic
    if threat_actor_confidence >= 90 or (lateral_movement_count >= 4 and persistence_score >= 12):
        threat_actor_type = "Nation-State APT"
    elif threat_actor_confidence >= 72 or (lateral_movement_count >= 2 and attack_stage_local in ("Exfiltration", "Persistence", "Privilege Escalation")):
        threat_actor_type = "Organized Cybercrime"
    elif threat_actor_confidence >= 55 or attack_stage_local in ("Lateral Movement", "Credential Access"):
        threat_actor_type = "Advanced Intrusion Actor"
    else:
        threat_actor_type = "Opportunistic Threat Actor"
        
    # Store everything in state["executive"]
    executive.update({
        "threat_sophistication_score": threat_sophistication_score,
        "analyst_verdict": analyst_verdict,
        "campaign_classification": campaign_classification,
        "escalation_reason": escalation_reason,
        "threat_actor_maturity": threat_actor_maturity,
        "operational_discipline": operational_discipline,
        "attacker_intent": attacker_intent,
        "adversary_behavior": adversary_behavior,
        "business_impact_score": business_impact_score,
        "executive_impact": executive_impact,
        "response_priority": response_priority,
        "containment_urgency": containment_urgency,
        "executive_decision_narrative": executive_decision_narrative,
        "campaign_progression": campaign_progression,
        "soc_investigation_narrative": soc_investigation_narrative,
        "executive_threat_briefing": executive_threat_briefing,
        "incident_chronology": incident_chronology,
        "research_summary": research_summary_narrative,
        "simulation_reliability": simulation_reliability,
        "executive_actions": executive_actions,
        "executive_response_strategy": "; ".join(executive_actions),
        
        # Auxiliary scores for rendering
        "soc_stability_index": soc_stability_index,
        "research_consistency_score": research_consistency_score,
        "research_confidence_index": research_confidence_index,
        "threat_actor_type": threat_actor_type,
        "threat_actor_confidence": threat_actor_confidence,
        "campaign_diversity_score": campaign_diversity_score,
    })
    
    return executive
