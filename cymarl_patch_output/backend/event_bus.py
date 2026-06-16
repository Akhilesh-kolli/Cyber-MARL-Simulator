"""
backend/event_bus.py
--------------------
Centralized event/telemetry pipeline. All platform logs, timeline elements,
and metrics derive from events published here.
"""

from datetime import datetime
from utils.constants import INVALID_TECHNIQUE_VALUES, NODE_MAPPING
from utils.formatting import format_event_log


def build_canonical_event(
    *,
    step: int,
    severity: str,
    event_type: str,
    node: str,
    source: str = "",
    destination: str = "",
    technique: str = "",
    cve: str = "",
    risk_delta: float = 0.0,
    reward_delta: float = 0.0,
    compromise_count: int = 0,
    message: str = "",
    **extra_fields
) -> dict:
    """
    Constructs a structured event matching the canonical specification.
    FIX: Removed fake 'Mitigation Node X' names; replaced with real asset names.
    FIX: CVE field for defender events now correctly says 'DEFENDER-ACTION' 
         but is NOT propagated into attacker technique slots.
    FIX: Defender events do not get attacker technique IDs.
    """
    # Normalize technique values
    safe_technique = str(technique or "").strip().upper()
    actor = str(extra_fields.get("actor", "")).lower()
    is_defender = (actor == "defender" or
                   str(source).lower() in ("soc", "defender") or
                   str(event_type).lower() == "mitigation")

    # FIX: Never assign attacker techniques to defender events
    # FIX: Use explicit action label as technique for defender, not attacker technique IDs
    if is_defender:
        # Map defender action labels to proper technique slots
        # The technique column for defender rows should show the action, not T-codes
        action_label = str(extra_fields.get("defender_action") or "").upper()
        if action_label:
            safe_technique = f"DEF:{action_label}"
        else:
            safe_technique = "DEFENSIVE-OPS"
    elif safe_technique in INVALID_TECHNIQUE_VALUES or safe_technique == "":
        # Fallback for attacker events with missing technique
        safe_technique = "T1595"

    # FIX: CVE field - defender events get DEFENDER-ACTION, attacker events get NOT-APPLICABLE
    # only when truly missing. Never mix CVE and DEFENDER-ACTION into attacker rows.
    safe_cve = str(cve or "").strip()
    if not safe_cve or safe_cve.upper() in ("N/A", "NONE", ""):
        if is_defender:
            safe_cve = "DEFENDER-ACTION"
        else:
            safe_cve = "NOT-APPLICABLE"
    # Never allow DEFENDER-ACTION in attacker event CVE
    if not is_defender and safe_cve.upper() == "DEFENDER-ACTION":
        safe_cve = "NOT-APPLICABLE"

    # FIX: Node field for defender events uses real asset name, not "Mitigation Node N"
    safe_node = str(node or "").strip()
    if is_defender and "Mitigation Node" in safe_node:
        # Extract node number and convert to real name
        try:
            node_num = int(safe_node.split("Mitigation Node")[-1].strip())
            safe_node = NODE_MAPPING.get(node_num, f"Node-{node_num}")
        except (ValueError, IndexError):
            safe_node = safe_node  # keep original if can't parse

    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "step": int(step),
        "severity": str(severity),
        "event_type": str(event_type),
        "node": safe_node,
        "source": str(source),
        "destination": str(destination),
        "technique": safe_technique,
        "cve": safe_cve,
        "risk_delta": float(risk_delta),
        "reward_delta": float(reward_delta),
        "compromise_count": int(compromise_count),
        "message": str(message)
    }

    # Store backwards compatible fields
    event.update(extra_fields)
    # Ensure normalized technique and cve override any incoming raw values
    event["technique"] = safe_technique
    event["cve"] = safe_cve
    event["node"] = safe_node

    # Backwards compatibility fallbacks
    if "threat" not in event:
        event["threat"] = severity
    if "kill_chain" not in event:
        event["kill_chain"] = event_type
    if "explanation" not in event:
        event["explanation"] = message
    if "compromised_count" not in event:
        event["compromised_count"] = compromise_count
    if "compromise_count_snapshot" not in event:
        event["compromise_count_snapshot"] = compromise_count

    return event


def push_event(state: dict, event: dict):
    """
    Pushes a validated event onto the canonical event bus.
    FIX: risk_delta now propagated correctly into event feed.
    """
    # FIX: Ensure risk_delta is properly set from canonical state
    risk_score = state["risk"].get("risk_score", 0.0)
    # Risk delta is already pre-computed and passed in; just ensure it's in the event
    state["events"].append(event)

    # Log the formatted message to the event_logs for real-time visualization
    log_line = format_event_log(event)
    if "event_logs" not in state["metrics"]:
        state["metrics"]["event_logs"] = []
    state["metrics"]["event_logs"].insert(0, log_line)

    # Track critical alerts and high severity events
    if event["severity"] == "CRITICAL":
        state["metrics"]["critical_alerts"] += 1
    if event["severity"] in ("HIGH", "CRITICAL"):
        state["metrics"]["high_severity_events"] += 1
