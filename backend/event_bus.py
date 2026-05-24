"""
backend/event_bus.py
--------------------
Centralized event/telemetry pipeline. All platform logs, timeline elements,
and metrics derive from events published here.
"""

from datetime import datetime
from utils.constants import INVALID_TECHNIQUE_VALUES
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
    # Normalize technique values and provide defensive mappings for missing techniques
    safe_technique = str(technique or "").strip().upper()
    actor = str(extra_fields.get("actor", "")).lower()

    # If technique is invalid or empty, attempt to infer defensive mappings
    if safe_technique in INVALID_TECHNIQUE_VALUES or safe_technique == "":
        expl = str(extra_fields.get("explanation", "") or "").lower()
        evt_sum = str(extra_fields.get("event_summary", "") or "").lower()
        detection_sig = str(extra_fields.get("detection_signature", "") or "").lower()
        combined_text = " ".join([expl, evt_sum, detection_sig])

        if actor == "defender" or source.lower() in ("soc", "defender") or str(event_type).lower() == "mitigation":
            # Heuristic defensive technique mappings
            if "isolate" in combined_text or "isolation" in combined_text:
                safe_technique = "T1565"
            elif "contain" in combined_text or "containment" in combined_text:
                safe_technique = "T1562"
            elif "mitig" in combined_text:
                safe_technique = "T1070"
            elif "detect" in combined_text or "detection" in combined_text or "signature" in combined_text:
                safe_technique = "T1057"
            elif "automation" in combined_text or "response automation" in combined_text:
                safe_technique = "T1489"
            else:
                safe_technique = "DEFENSIVE-OPS"
        else:
            # Default attacker fallback (recon-like placeholder)
            safe_technique = "T1595"

    # Normalize CVE field using defender-aware placeholders
    safe_cve = str(cve or "").strip()
    if not safe_cve or safe_cve.upper() in ("N/A", "NONE", ""):
        if actor == "defender" or source.lower() in ("soc", "defender"):
            safe_cve = "DEFENDER-ACTION"
        else:
            safe_cve = "NOT-APPLICABLE"

    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "step": int(step),
        "severity": str(severity),
        "event_type": str(event_type),
        "node": str(node),
        "source": str(source),
        "destination": str(destination),
        "technique": safe_technique,
        "cve": safe_cve,
        "risk_delta": float(risk_delta),
        "reward_delta": float(reward_delta),
        "compromise_count": int(compromise_count),
        "message": str(message)
    }

    # Store backwards compatible fields in the event dict as well
    event.update(extra_fields)
    # Ensure normalized technique and cve override any incoming raw values
    event["technique"] = safe_technique
    event["cve"] = safe_cve
    
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
