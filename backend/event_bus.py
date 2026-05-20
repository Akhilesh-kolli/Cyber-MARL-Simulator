"""
backend/event_bus.py
--------------------
Centralized event/telemetry pipeline. All platform logs, timeline elements,
and metrics derive from events published here.
"""

from datetime import datetime
from utils.constants import VALID_TECHNIQUES, INVALID_TECHNIQUE_VALUES
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
    Also retains extra fields to ensure backwards compatibility with existing pipelines.
    """
    safe_technique = technique if technique in VALID_TECHNIQUES else ""
    if safe_technique in INVALID_TECHNIQUE_VALUES:
        safe_technique = ""

    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "step": int(step),
        "severity": str(severity),
        "event_type": str(event_type),
        "node": str(node),
        "source": str(source),
        "destination": str(destination),
        "technique": safe_technique,
        "cve": str(cve),
        "risk_delta": float(risk_delta),
        "reward_delta": float(reward_delta),
        "compromise_count": int(compromise_count),
        "message": str(message)
    }

    # Store backwards compatible fields in the event dict as well
    event.update(extra_fields)
    
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
    """
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
