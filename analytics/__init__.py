"""
analytics/__init__.py
---------------------
Package init — re-exports all public analytics utilities so that code
doing `from analytics import build_chart_df` continues to work after the
analytics/ sub-package was created alongside the flat analytics.py file.

Sub-modules available:
  analytics.mitre_mapper       — MITRE technique frequency helpers
  analytics.ioc_engine         — IOCEngine indicator compiler
  analytics.executive_analytics — Executive narrative generator
  analytics.anomaly_engine     — Anomaly pressure & volatility math
  analytics.hunt_analytics     — Threat hunt summary builder
  analytics.metrics_aggregator — Master aggregation coordinator
"""

import pandas as pd
import plotly.express as px

# ---------------------------------------------------------------------------
# Shared threat-level numeric mapping
# ---------------------------------------------------------------------------
THREAT_NUMERIC = {
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4,
}


# ---------------------------------------------------------------------------
# TIMELINE DATAFRAME
# ---------------------------------------------------------------------------
def build_timeline_df(events: list) -> pd.DataFrame:
    """
    Build timeline DataFrame from structured canonical event list.
    Returns columns: Time, Stage, Threat, Event, ThreatScore, Actor,
                     timeline_weight (optional)
    """
    try:
        from utils.formatting import format_event_log
    except ImportError:
        try:
            from event_engine import format_event_log
        except ImportError:
            def format_event_log(e):
                return e.get("message", str(e))

    rows = []
    cumulative = 0.0
    for idx, e in enumerate(events):
        label = format_event_log(e)
        base_score = THREAT_NUMERIC.get(e.get("threat", e.get("severity", "LOW")), 0)
        # Organic escalation: cumulative sum + index-based growth + small variance
        cumulative += base_score * (1 + idx * 0.04)
        escalation_score = round(cumulative, 2)
        technique = e.get("technique") or e.get("mitre_name") or "N/A"
        target_node = e.get("node") or e.get("node_type") or "Unknown"
        source_node = e.get("source") or "Attacker"
        confidence = e.get("detection_confidence") if e.get("detection_confidence") is not None else e.get("confidence", 0)
        status = e.get("status", "unknown")
        summary = e.get("event_summary") or e.get("message", "")
        if not summary:
            if e.get("actor") == "defender":
                summary = f"Defender action executed against {target_node}."
            elif e.get("kill_chain", "").lower() == "reconnaissance":
                summary = f"Port scan detected against {target_node}."
            elif e.get("kill_chain", "").lower() == "discovery":
                summary = f"Network discovery activity observed on {target_node}."
            elif e.get("kill_chain", "").lower() == "initial access":
                summary = f"{technique} attempt against {target_node}."
            elif e.get("kill_chain", "").lower() == "execution":
                summary = f"Suspicious service execution on {target_node}."
            elif e.get("kill_chain", "").lower() == "persistence":
                summary = f"Persistence behavior detected on {target_node}."
            elif e.get("kill_chain", "").lower() == "privilege escalation":
                summary = f"Privilege escalation attempt detected on {target_node}."
            elif e.get("kill_chain", "").lower() == "lateral movement":
                summary = f"Lateral movement from {source_node} to {target_node}."
            elif e.get("kill_chain", "").lower() == "collection":
                summary = f"Data collection activity observed on {target_node}."
            elif e.get("kill_chain", "").lower() == "exfiltration":
                summary = f"Suspicious outbound transfer from {target_node}."
            elif e.get("kill_chain", "").lower() == "command and control":
                summary = f"Command and control channel established by {source_node}."
            elif e.get("kill_chain", "").lower() == "mitigation":
                summary = f"Defender isolated compromised {target_node}."
            else:
                summary = e.get("message", "No summary available.")

        row = {
            "Event ID":    idx + 1,
            "Time":        e.get("timestamp", ""),
            "Stage":       e.get("kill_chain", e.get("event_type", "Unknown")),
            "Severity":    e.get("threat", e.get("severity", "LOW")),
            "Threat":      e.get("threat", e.get("severity", "LOW")),
            "Technique":   technique,
            "Target Node": target_node,
            "Source Node": source_node,
            "CVE":         e.get("cve", "N/A"),
            "Actor":       str(e.get("actor", "unknown")).capitalize(),
            "Confidence":  confidence,
            "Status":      status,
            "Event Summary": summary,
            "Event":       label,
            "ThreatScore": escalation_score,
        }
        if "timeline_weight" in e:
            row["timeline_weight"] = e["timeline_weight"]
        rows.append(row)

    cols = [
        "Event ID", "Time", "Stage", "Severity", "Threat", "Technique",
        "Target Node", "Source Node", "CVE", "Actor", "Confidence",
        "Status", "Event Summary", "Event", "ThreatScore"
    ]
    return pd.DataFrame(rows, columns=cols) if rows else pd.DataFrame(columns=cols)


# ---------------------------------------------------------------------------
# THREAT ANALYTICS CHART DATAFRAME
# ---------------------------------------------------------------------------
def build_chart_df(
    step_history:       list,
    threat_history:     list,
    compromise_history: list,
    defense_history:    list = None,
    momentum_history:   list = None,
) -> pd.DataFrame:
    """
    Build the multi-series chart DataFrame ensuring all arrays are equal length.
    Pads shorter arrays with None to match the longest series.
    """
    n = min(len(step_history), len(threat_history), len(compromise_history))
    if n == 0:
        return pd.DataFrame(columns=["Step", "Critical Alerts", "Compromised Nodes"])

    data = {
        "Step":              step_history[:n],
        "Critical Alerts":   threat_history[:n],
        "Compromised Nodes": compromise_history[:n],
    }
    if defense_history is not None:
        dn = min(n, len(defense_history))
        data["Successful Defenses"] = defense_history[:dn] + [None] * (n - dn)
    if momentum_history is not None:
        mn = min(n, len(momentum_history))
        data["Threat Momentum"] = momentum_history[:mn] + [None] * (n - mn)

    return pd.DataFrame(data)


# ---------------------------------------------------------------------------
# MITRE PIE CHART
# ---------------------------------------------------------------------------
def build_mitre_pie(technique_counts: dict):
    """
    Build a Plotly donut chart from technique_counts dict.
    Returns None if no active techniques.
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
        hole=0.40,
    )
    fig.update_layout(
        autosize=True,
        paper_bgcolor="#071028",
        plot_bgcolor="#071028",
        font_color="white",
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.1,
            xanchor="center",
            x=0.5,
            font=dict(size=10),
        ),
        margin=dict(l=10, r=10, t=40, b=40),
        height=350
    )
    return fig


# ---------------------------------------------------------------------------
# MITRE FREQUENCY TABLE
# ---------------------------------------------------------------------------
def build_mitre_table(technique_counts: dict) -> pd.DataFrame:
    return (
        pd.DataFrame({
            "Technique": list(technique_counts.keys()),
            "Frequency": list(technique_counts.values()),
        })
        .sort_values("Frequency", ascending=False)
        .reset_index(drop=True)
    )


# ---------------------------------------------------------------------------
# THREAT ESCALATION TREND CHART
# ---------------------------------------------------------------------------
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
        color_discrete_sequence=px.colors.qualitative.Safe,
    )
    fig.update_layout(
        autosize=True,
        paper_bgcolor="#071028",
        plot_bgcolor="#071028",
        font_color="white",
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(size=10),
        ),
        xaxis=dict(showgrid=True, gridcolor="#1e293b", title="Event"),
        yaxis=dict(showgrid=True, gridcolor="#1e293b", title="Cumulative Threat Score"),
        margin=dict(l=10, r=10, t=40, b=50),
        height=350
    )
    return fig


# ---------------------------------------------------------------------------
# FILTER TIMELINE
# ---------------------------------------------------------------------------
def filter_timeline(timeline_df: pd.DataFrame, threat_filter: str) -> pd.DataFrame:
    if threat_filter == "ALL" or timeline_df.empty:
        return timeline_df
    return timeline_df[timeline_df["Threat"] == threat_filter]


# ---------------------------------------------------------------------------
# SOC REPORT CSV EXPORT
# ---------------------------------------------------------------------------
def export_soc_report(timeline_df: pd.DataFrame) -> bytes:
    return timeline_df.to_csv(index=False).encode("utf-8")
