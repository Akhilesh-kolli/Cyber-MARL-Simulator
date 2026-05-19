"""
event_engine.py
---------------
Central structured event dictionary.
ALL parts of the pipeline read from this — no string parsing anywhere.
"""

from datetime import datetime

# --------------------------------------------------
# SIMULATION NODE DEFINITIONS  (graph topology)
# --------------------------------------------------
SIMULATION_NODES = {
    0: "Workstation",
    1: "Firewall",
    2: "Database",
    3: "Server",
    4: "DomainController",
    5: "Workstation",
}

# --------------------------------------------------
# REAL SERVICE TARGETS  (actual lab services)
# --------------------------------------------------
REAL_SERVICES = {
    "DVWA":  {"port": 8080, "protocol": "HTTP"},
    "MySQL": {"port": 3307, "protocol": "TCP"},
    "Nginx": {"port": 5000, "protocol": "HTTP"},
}

# Maps simulation node_id -> real service name
NODE_TO_SERVICE = {
    0: "Nginx",
    1: "DVWA",
    2: "MySQL",
}

# --------------------------------------------------
# VULNERABILITY DATABASE
# --------------------------------------------------
VULNERABILITY_DB = {
    "DVWA": {
        "cve":      "CVE-2023-9999",
        "name":     "SQL Injection",
        "cvss":     9.8,
        "mitre":    "T1190",
        "severity": "CRITICAL",
    },
    "MySQL": {
        "cve":      "CVE-2016-6662",
        "name":     "MySQL Remote Root Code Execution",
        "cvss":     8.5,
        "mitre":    "T1021",
        "severity": "HIGH",
    },
    "Nginx": {
        "cve":      "CVE-2021-23017",
        "name":     "Nginx Resolver RCE",
        "cvss":     7.7,
        "mitre":    "T1190",
        "severity": "HIGH",
    },
}

# --------------------------------------------------
# DETECTION RULES
# --------------------------------------------------
DETECTION_RULES = {
    "SQL Injection": {
        "signature":  "ET WEB_SERVER SQL Injection Attempt",
        "severity":   "HIGH",
        "confidence": 92,
    },
    "Active Scanning": {
        "signature":  "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "severity":   "MEDIUM",
        "confidence": 81,
    },
    "Remote Services": {
        "signature":  "SIGMA Lateral Movement Remote Service Execution",
        "severity":   "HIGH",
        "confidence": 88,
    },
    "Network Service Discovery": {
        "signature":  "ET POLICY Internal Network Scan",
        "severity":   "LOW",
        "confidence": 73,
    },
}

# --------------------------------------------------
# MITRE -> SEVERITY MAPPING
# --------------------------------------------------
ATTACK_SEVERITY = {
    "T1190": "CRITICAL",
    "T1021": "HIGH",
    "T1046": "MEDIUM",
    "T1595": "LOW",
}

# --------------------------------------------------
# VALID TECHNIQUE IDs  (never log UNKNOWN / N/A)
# --------------------------------------------------
VALID_TECHNIQUES = {"T1190", "T1021", "T1046", "T1595"}
INVALID_TECHNIQUE_VALUES = {"N/A", "UNKNOWN", None, ""}


# --------------------------------------------------
# CORE: build_event()
# Returns a fully structured event dict.
# Everything downstream reads FROM this object.
# --------------------------------------------------
def build_event(
    *,
    actor,
    node_id,
    node_type,
    service,
    technique,
    tactic,
    mitre_name,
    kill_chain,
    threat,
    port,
    cve,
    cvss,
    status,
    vulnerability,
    detection_signature,
    detection_severity,
    detection_confidence,
    timeline_weight=0,
    explanation,
    compromised_count,
    step,
):
    """
    Single source of truth for every simulation event.
    actor: 'attacker' | 'defender'
    status: 'success' | 'failed' | 'defender'
    """
    # Sanitise technique — never store UNKNOWN or N/A
    safe_technique = technique if technique in VALID_TECHNIQUES else ""

    return {
        "timestamp":            datetime.now().strftime("%H:%M:%S"),
        "step":                 step,
        "actor":                actor,
        "node_id":              node_id,
        "node_type":            node_type,
        "service":              service,
        "technique":            safe_technique,
        "tactic":               tactic,
        "mitre_name":           mitre_name,
        "kill_chain":           kill_chain,
        "threat":               threat,
        "port":                 port,
        "cve":                  cve,
        "cvss":                 cvss,
        "status":               status,
        "vulnerability":        vulnerability,
        "detection_signature":  detection_signature,
        "detection_severity":   detection_severity,
        "detection_confidence": detection_confidence,
        "timeline_weight":      timeline_weight,
        "explanation":          explanation,
        "compromised_count":    compromised_count,
    }


def format_event_log(event):
    """
    Render a structured event dict into a human-readable log line.
    Reads directly from event fields — zero string parsing.
    """
    parts = [f"[{event['timestamp']}]"]

    if event["actor"] == "attacker":
        parts.append(f"Attack Node {event['node_id']}")

        if event["status"] == "success":
            if event["port"]:
                parts.append(f"Port {event['port']} Open")
            if event.get("vulnerability"):
                parts.append(f"HTTP 200 | {event['vulnerability']}")
        else:
            parts.append("Service Unreachable")

        if event["technique"]:
            parts.append(
                f"{event['technique']} {event['mitre_name']} [{event['tactic']}]"
            )

        parts.append(f"Stage: {event['kill_chain']}")
        parts.append(f"Threat: {event['threat']}")

        if event["cve"] and event["cve"] != "N/A":
            parts.append(f"CVE: {event['cve']}")
        if event["cvss"] is not None:
            parts.append(f"CVSS: {event['cvss']}")
        if event["detection_signature"] and event["detection_signature"] != "N/A":
            parts.append(f"ALERT: {event['detection_signature']}")

    else:
        parts.append("Defender Action")
        parts.append(f"Stage: {event['kill_chain']}")
        parts.append(f"Threat: {event['threat']}")

    parts.append(f"Reason: {event['explanation']}")
    parts.append(f"Compromised Nodes: {event['compromised_count']}")

    return " | ".join(parts)
