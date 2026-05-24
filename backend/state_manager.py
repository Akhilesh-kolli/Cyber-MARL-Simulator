"""
backend/state_manager.py
------------------------
Authoritative state manager. Initializes, validates, and serializes
the canonical simulation state structure.
"""

from datetime import datetime
from utils.constants import SIMULATION_NODES

def get_initial_state() -> dict:
    """
    Returns a fresh canonical simulation state dictionary.
    """
    nodes = {}
    for i in range(6):
        role = SIMULATION_NODES.get(i, "Workstation")
        hostname = "Domain-Controller" if i == 4 else f"Host-{i}"
        nodes[i] = {
            "id": i,
            "hostname": hostname,
            "role": role,
            "status": "healthy",
            "risk_score": 0.0,
            "compromise_stage": "None",
            "severity": "LOW",
            "techniques": [],
            "ports": [],
            "events": [],
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attacker_present": False,
            "defender_action": "None"
        }

    return {
        "simulation": {
            "status": "initialized",
            "step": 0,
            "start_time": None,
            "end_time": None,
            "elapsed_time": 0,
            "reward": 0.0,
            "running": False,
            "completed": False
        },
        "nodes": nodes,
        "events": [],
        "alerts": [],
        "timeline": [],
        "ioc_registry": [],
        "metrics": {
            "risk_score": 0.0,
            "incident_priority": "LOW",
            "incident_status": "IDLE",
            "threat_level": "LOW",
            "ioc_ports": set(),
            "ioc_techniques": set(),
            "compromised_assets": set(),
            "observed_attack_stages": set(),
            "critical_alerts": 0,
            "high_severity_events": 0,
            "recon_events": 0,
            "discovery_events": 0,
            "lateral_movement_count": 0,
            "attack_attempts": 0,
            "successful_attacks": 0,
            "successful_defenses": 0,
            "failed_defenses": 0,
            "defense_actions_count": 0,
            "threat_momentum_score": 0,
            "persistence_score": 0,
            "threat_correlation_score": 0,
            "containment_pressure_score": 0,
            "threat_volatility_score": 0,
            "anomaly_pressure_score": 0,
            "tactical_recommendation": "Awaiting Simulation",
            "executive_response_strategy": "Awaiting Simulation",
            "attacker_profile": "Unknown",
            "campaign_type": "Unknown Campaign",
            "timeline_data": [],
            "structured_events": [],
            "event_logs": [],
            "step_history": [],
            "threat_history": [],
            "compromise_history": [],
            "sqli_detected": 0,
            "alert_fatigue_score": 0.0,
            "alert_confidence_total": 0.0,
            "alert_count": 0,
            "technique_counts": {
                "T1190": 0,
                "T1021": 0,
                "T1046": 0,
                "T1059": 0,
                "T1078": 0,
                "T1003": 0,
                "T1105": 0,
                "T1562": 0,
                "T1055": 0,
                "T1547": 0,
                "T1486": 0,
                "T1110": 0,
                "T1595": 0
            },
            "average_alert_confidence": 0.0,
            "compromised_count": 0,
            "estimated_dwell_time": 0,
            "total_reward": 0.0,
            "defense_effectiveness": 0.0,
            "attack_success_rate": 0.0,
            "attack_stage": "Idle",
            "defense_history": [],
            "momentum_history": []
        },
        "risk": {
            "risk_score": 0.0,
            "incident_priority": "LOW",
            "incident_status": "IDLE",
            "threat_level": "LOW"
        },
        "graph": {
            "nodes": [],
            "edges": []
        },
        "mitre": {
            "technique_counts": {
                "T1190": 0,
                "T1021": 0,
                "T1046": 0,
                "T1595": 0
            }
        },
        "executive": {
            "analyst_verdict": "System standby. Awaiting attack execution.",
            "campaign_classification": "N/A",
            "operational_discipline": "N/A",
            "incident_chronology": "No threat activity recorded.",
            "executive_impact": "None currently.",
            "response_priority": "Routine SOC monitoring.",
            "attacker_intent": "Unknown",
            "escalation_reason": "No active incidents.",
            "executive_threat_briefing": "All networks operating normally.",
            "adversary_behavior": "N/A",
            "executive_decision_narrative": "No response action required.",
            "campaign_progression": "N/A",
            "soc_investigation_narrative": "No alert telemetry generated.",
            "research_summary": "Awaiting simulation loop.",
            "simulation_reliability": "N/A"
        }
    }

def initialize_session_state(st):
    """
    Ensures simulation_state exists in Streamlit session state and is fully populated.
    """
    if "simulation_state" not in st.session_state:
        st.session_state.simulation_state = get_initial_state()
    
    # Forward compatibility aliases
    st.session_state.simulation_data = st.session_state.simulation_state
    
    # Keep session state flags synced with canonical state status
    status = st.session_state.simulation_state["simulation"]["status"]
    # `simulation_started` should reflect an actively running simulation only.
    # Do NOT treat a completed status as "started" to avoid UI thinking
    # the simulation is still active after it finishes.
    st.session_state.simulation_started = (status == "running")
    st.session_state.simulation_complete = (status == "completed")

    # Authoritative visual and threat metrics cache initialization
    if "network_graph_fig" not in st.session_state:
        st.session_state.network_graph_fig = None
    if "alert_fatigue_score" not in st.session_state:
        st.session_state.alert_fatigue_score = 0

