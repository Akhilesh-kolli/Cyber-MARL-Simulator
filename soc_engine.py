"""
soc_engine.py
-------------
SOC state manager.
Maintains all counters, calls risk_engine for scores,
and exposes a single snapshot() dict for the dashboard to render.

Reads structured event dicts — no string parsing.
"""

from risk_engine import (
    calculate_risk_score,
    get_incident_priority,
    get_incident_status,
    get_threat_level,
    get_attacker_profile,
    get_soc_recommendation,
    get_dwell_time,
    get_alert_fatigue_score,
    get_attack_success_rate,
    get_defense_effectiveness,
    get_dominant_technique,
)


class SOCEngine:
    """
    Central SOC state machine.
    Call .ingest(event) for every structured event.
    Call .snapshot() to get a plain dict for the dashboard.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        # Counters
        self.step                  = 0
        self.critical_alerts       = 0
        self.high_severity_events  = 0
        self.sqli_detected         = 0
        self.recon_events          = 0
        self.discovery_events      = 0
        self.lateral_movement_count = 0

        # Attack / defense tallies
        self.attack_attempts    = 0
        self.successful_attacks = 0
        self.defense_actions    = 0
        self.successful_defenses = 0

        # Technique frequency
        self.technique_counts = {
            "T1190": 0,
            "T1021": 0,
            "T1046": 0,
            "T1595": 0,
        }

        # State
        self.compromised_count = 0
        self.total_reward      = 0.0

        # Accumulated events for CVSS-weighted risk
        self._events = []

    # --------------------------------------------------
    def ingest(self, event: dict, reward: float = 0.0):
        """Process one structured event — update all counters."""
        self.step             = event.get("step", self.step)
        self.compromised_count = event.get("compromised_count", self.compromised_count)
        self.total_reward    += reward
        self._events.append(event)

        threat     = event.get("threat", "LOW")
        technique  = event.get("technique", "")
        kill_chain = event.get("kill_chain", "")
        actor      = event.get("actor", "")
        status     = event.get("status", "")
        tactic     = event.get("tactic", "").lower()

        # Threat-level counters
        if threat == "CRITICAL":
            self.critical_alerts += 1
        if threat in ("HIGH", "CRITICAL"):
            self.high_severity_events += 1

        # Technique counters — only valid IDs
        if technique and technique in self.technique_counts:
            self.technique_counts[technique] += 1
        elif technique and technique not in ("", None):
            # New technique not in default dict — add it
            self.technique_counts[technique] = \
                self.technique_counts.get(technique, 0) + 1

        # Tactic / kill chain counters
        if "recon" in kill_chain.lower() or "recon" in tactic:
            self.recon_events += 1
        if "discovery" in kill_chain.lower() or "discovery" in tactic:
            self.discovery_events += 1
        if "lateral" in kill_chain.lower() or "lateral" in tactic:
            self.lateral_movement_count += 1

        # SQLi detection
        if event.get("vulnerability", "") == "SQL Injection Detected":
            self.sqli_detected += 1

        # Attack / defense tallies
        if actor == "attacker":
            self.attack_attempts += 1
            if status == "success":
                self.successful_attacks += 1

        elif actor == "defender":
            self.defense_actions += 1
            if status == "success":
                self.successful_defenses += 1

    # --------------------------------------------------
    def snapshot(self) -> dict:
        """
        Return a plain dict with all computed SOC metrics.
        The dashboard renders exclusively from this dict.
        """
        risk_score        = calculate_risk_score(
            self.critical_alerts,
            self.high_severity_events,
            self.compromised_count,
            self.successful_attacks,
            self._events,
        )
        incident_priority = get_incident_priority(risk_score)
        incident_status   = get_incident_status(risk_score, self.compromised_count)
        attacker_profile  = get_attacker_profile(risk_score, self.lateral_movement_count)
        soc_recommendation = get_soc_recommendation(incident_priority)
        dominant_technique = get_dominant_technique(self.technique_counts)

        return {
            # Core
            "step":                   self.step,
            "total_reward":           round(self.total_reward, 2),
            "compromised_count":      self.compromised_count,

            # Risk
            "risk_score":             risk_score,
            "incident_priority":      incident_priority,
            "incident_status":        incident_status,
            "dominant_technique":     dominant_technique,
            "technique_counts":       dict(self.technique_counts),

            # Profiling
            "attacker_profile":       attacker_profile,
            "soc_recommendation":     soc_recommendation,
            "estimated_dwell_time":   get_dwell_time(self.compromised_count),

            # Counters
            "critical_alerts":        self.critical_alerts,
            "high_severity_events":   self.high_severity_events,
            "sqli_detected":          self.sqli_detected,
            "recon_events":           self.recon_events,
            "discovery_events":       self.discovery_events,
            "lateral_movement_count": self.lateral_movement_count,

            # Rates
            "attack_success_rate":   get_attack_success_rate(
                self.successful_attacks, self.attack_attempts
            ),
            "defense_effectiveness": get_defense_effectiveness(
                self.successful_defenses, self.defense_actions
            ),
            "alert_fatigue_score":   get_alert_fatigue_score(
                self.critical_alerts, self.step + 1
            ),
        }
