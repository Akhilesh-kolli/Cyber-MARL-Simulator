"""
analytics.py
------------
Chart and analytics helpers.
All functions accept structured event lists or SOC snapshots.
Zero string parsing.
"""

import pandas as pd
import plotly.express as px


THREAT_NUMERIC = {
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4,
}


# --------------------------------------------------
# TIMELINE DATAFRAME
# --------------------------------------------------
def build_timeline_df(events: list) -> pd.DataFrame:
    """
    Build timeline DataFrame from structured event list.
    Returns columns: Event ID, Time, Stage, Severity, Technique, Target Node, Source Node, CVE, Actor, Confidence, Status, Event Summary, ThreatScore
    """
    rows = []
    cumulative = 0.0
    for idx, e in enumerate(events):
        base_score = THREAT_NUMERIC.get(e.get("threat", e.get("severity", "LOW")), 0)
        cumulative += base_score * (1 + idx * 0.04)
        escalation_score = round(cumulative, 2)
        stage = e.get("kill_chain", e.get("event_type", "Unknown"))
        technique = e.get("technique") or e.get("mitre_name") or "N/A"
        target_node = e.get("node") or e.get("node_type") or "Unknown"
        source_node = e.get("source") or "Attacker"
        confidence = e.get("detection_confidence") if e.get("detection_confidence") is not None else e.get("confidence", 0)
        status = e.get("status", "unknown")
        summary = e.get("event_summary") or e.get("message", "")
        if not summary:
            if e.get("actor") == "defender":
                summary = f"Defender action executed against {target_node}."
            elif stage == "Reconnaissance":
                summary = f"Port scan detected against {target_node}"
            elif stage == "Discovery":
                summary = f"Network discovery activity observed on {target_node}"
            elif stage == "Initial Access":
                summary = f"{technique} attempt against {target_node}"
            elif stage == "Execution":
                summary = f"Suspicious service execution on {target_node}"
            elif stage == "Persistence":
                summary = f"Persistence behavior detected on {target_node}"
            elif stage == "Privilege Escalation":
                summary = f"Privilege escalation attempt detected on {target_node}"
            elif stage == "Lateral Movement":
                summary = f"Lateral movement from {source_node} to {target_node}"
            elif stage == "Collection":
                summary = f"Data collection activity observed on {target_node}"
            elif stage == "Exfiltration":
                summary = f"Suspicious outbound transfer from {target_node}"
            elif stage == "Command and Control":
                summary = f"Command and control channel established by {source_node}"
            elif stage == "Mitigation":
                summary = f"Defender isolated compromised {target_node}"
            else:
                summary = e.get("message", "No summary available.")

        rows.append({
            "Event ID":    idx + 1,
            "Time":        e.get("timestamp", ""),
            "Stage":       stage,
            "Severity":    e.get("threat", e.get("severity", "LOW")),
            "Technique":   technique,
            "Target Node": target_node,
            "Source Node": source_node,
            "CVE":         e.get("cve", "N/A"),
            "Actor":       str(e.get("actor", "unknown")).capitalize(),
            "Confidence":  confidence,
            "Status":      status,
            "Event Summary": summary,
            "ThreatScore": escalation_score,
        })

    columns = [
        "Event ID", "Time", "Stage", "Severity", "Technique", "Target Node",
        "Source Node", "CVE", "Actor", "Confidence", "Status", "Event Summary", "ThreatScore"
    ]
    return pd.DataFrame(rows, columns=columns) if rows else pd.DataFrame(columns=columns)


# --------------------------------------------------
# THREAT ANALYTICS CHART DATA
# --------------------------------------------------
def build_chart_df(
    step_history:        list,
    threat_history:      list,
    compromise_history:  list,
    defense_history:     list = None,
    momentum_history:    list = None,
) -> pd.DataFrame:
    data = {
        "Step":              step_history,
        "Critical Alerts":   threat_history,
        "Compromised Nodes": compromise_history,
    }
    if defense_history is not None:
        data["Successful Defenses"] = defense_history
    if momentum_history is not None:
        data["Threat Momentum"] = momentum_history
    return pd.DataFrame(data)



# --------------------------------------------------
# MITRE PIE CHART
# --------------------------------------------------
def build_mitre_pie(technique_counts: dict):
    """
    Build a Plotly pie chart from technique_counts dict.
    Only includes techniques with frequency > 0.
    """
    active = {k: v for k, v in technique_counts.items() if v > 0}

    if not active:
        return None

    df = pd.DataFrame({
        "Technique": list(active.keys()),
        "Frequency": list(active.values()),
    })

    fig = px.pie(
        df,
        names="Technique",
        values="Frequency",
        title="MITRE ATT&CK Technique Distribution",
        color_discrete_sequence=px.colors.sequential.Blues_r,
        hole=0.35,
    )
    return fig



# --------------------------------------------------
# MITRE FREQUENCY TABLE
# --------------------------------------------------
def build_mitre_table(technique_counts: dict) -> pd.DataFrame:
    return pd.DataFrame({
        "Technique": list(technique_counts.keys()),
        "Frequency": list(technique_counts.values()),
    }).sort_values("Frequency", ascending=False).reset_index(drop=True)


# --------------------------------------------------
# THREAT ESCALATION TREND
# --------------------------------------------------
def build_escalation_chart(timeline_df: pd.DataFrame):
    """
    Line chart of ThreatScore over time, coloured by kill chain stage.
    """
    if timeline_df.empty:
        return None

    fig = px.line(
        timeline_df.head(25),
        x="Time",
        y="ThreatScore",
        color="Stage",
        title="Threat Escalation Trend",
        markers=True,
    )
    return fig


# --------------------------------------------------
# FILTER TIMELINE
# --------------------------------------------------
def filter_timeline(timeline_df: pd.DataFrame, threat_filter: str) -> pd.DataFrame:
    if threat_filter == "ALL" or timeline_df.empty:
        return timeline_df
    return timeline_df[timeline_df["Threat"] == threat_filter]


# --------------------------------------------------
# SOC REPORT CSV
# --------------------------------------------------
def export_soc_report(timeline_df: pd.DataFrame) -> bytes:
    return timeline_df.to_csv(index=False).encode("utf-8")
