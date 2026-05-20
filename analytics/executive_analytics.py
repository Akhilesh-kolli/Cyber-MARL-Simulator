"""
analytics/executive_analytics.py
--------------------------------
Generates high-level narrative intelligence, threat actor maturity profiles,
operational discipline matrices, and executive-level briefings.
"""

from analytics.mitre_mapper import get_dominant_technique

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
    
    # 1. Step History/Step calculations
    step = state["simulation"]["step"]
    
    # 2. Campaign Diversity Score
    campaign_diversity_score = min(
        100,
        (len(metrics.get("ioc_techniques", [])) * 6)
        + (len(metrics.get("observed_attack_stages", [])) * 10)
        + (lateral_movement_count * 3)
    )
    
    # 3. Sophistication Score
    threat_sophistication_score = min(
        100,
        int(
            (threat_momentum_score * 0.35)
            + (persistence_score * 1.8)
            + (lateral_movement_count * 4)
            + (len(metrics.get("ioc_techniques", [])) * 3)
            + (campaign_diversity_score * 0.25)
        )
    )
    
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
        + (threat_momentum_score * 0.25)
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
    
    # 11. Business Impact
    business_impact_score = min(
        100.0,
        (compromised_count * 10)
        + (critical_alerts * 4)
        + (persistence_score * 1.5)
        + (threat_momentum_score * 0.4)
    )
    
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
    
    # 15. Executive Decision Narrative
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
    soc_investigation_narrative = (
        f"SOC telemetry identified {len(metrics.get('ioc_techniques', []))} attack techniques "
        f"across {len(metrics.get('ioc_ports', []))} observed ports. "
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
    
    # 20. Advanced Performance Indices
    soc_stability_index = max(
        25.0,
        100.0
        - (compromised_count * 8)
        - (critical_alerts * 1.5)
        - (threat_momentum_score * 0.18)
        - (anomaly_pressure_score * 0.12)
    )
    research_consistency_score = max(
        0.0,
        100.0
        - (threat_volatility_score * 0.45)
        - (anomaly_pressure_score * 0.30)
        - (containment_pressure_score * 0.20)
    )
    research_consistency_score = min(
        100.0,
        research_consistency_score + (average_alert_confidence * 0.05)
    )
    
    # 21. Research Confidence Index & reliability
    research_confidence_index = min(
        100.0,
        (average_alert_confidence * 0.30)
        + (threat_correlation_score * 0.25)
        + (research_consistency_score * 0.25)
        + (soc_stability_index * 0.20)
    )
    
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
    
    # 23. Threat Actor Profile & Attribution
    if persistence_score >= 12 and threat_correlation_score >= 40:
        threat_actor_confidence = 95
    elif lateral_movement_count >= 4 and campaign_diversity_score >= 50:
        threat_actor_confidence = 82
    elif recon_events >= 5 and discovery_events >= 5:
        threat_actor_confidence = 68
    else:
        threat_actor_confidence = 45

    if threat_actor_confidence >= 90:
        threat_actor_type = "Nation-State APT"
    elif threat_actor_confidence >= 75:
        threat_actor_type = "Organized Cybercrime"
    elif threat_actor_confidence >= 60:
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
        
        # Auxiliary scores for rendering
        "soc_stability_index": soc_stability_index,
        "research_consistency_score": research_consistency_score,
        "research_confidence_index": research_confidence_index,
        "threat_actor_type": threat_actor_type,
        "threat_actor_confidence": threat_actor_confidence,
        "campaign_diversity_score": campaign_diversity_score,
    })
    
    return executive
