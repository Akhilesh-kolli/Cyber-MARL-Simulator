"""
utils/formatting.py
------------------
Formatter helpers for telemetry events, logs, and dates.
"""

from datetime import datetime

def format_event_log(event: dict) -> str:
    """
    Render a structured event dict into a human-readable log line.
    Reads directly from event fields — zero string parsing.
    """
    timestamp = event.get("timestamp", datetime.now().strftime("%H:%M:%S"))
    stage = event.get("kill_chain", "UNKNOWN")
    node_type = event.get("node_type", "Unknown")
    node_id = event.get("node_id", -1)
    severity = event.get("threat", "INFO")
    technique = event.get("technique", "None") or "None"
    cve = event.get("cve", "N/A")
    risk_delta = event.get("risk_delta", 0)
    compromise_count = event.get("compromise_count_snapshot", event.get("compromised_count", 0))
    explanation = event.get("explanation", "")

    # Clean display
    node_str = f"{node_type} ({node_id})" if node_id != -1 else node_type

    return (
        f"[{timestamp}] [{stage.upper()}] Node: {node_str} | "
        f"Severity: {severity} | Tech: {technique} | CVE: {cve} | "
        f"Risk: {risk_delta:+d} | Compromised: {compromise_count}/6 | {explanation}"
    )
