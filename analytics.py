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
    Returns columns: Time, Stage, Threat, Event, ThreatScore, Actor
    """
    from event_engine import format_event_log
    rows = []
    for e in events:
        label = format_event_log(e)

        rows.append({
            "Time":        e["timestamp"],
            "Stage":       e["kill_chain"],
            "Threat":      e["threat"],
            "Event":       label,
            "ThreatScore": THREAT_NUMERIC.get(e["threat"], 0),
            "Actor":       e["actor"].capitalize(),
        })

    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Time", "Stage", "Threat", "Event", "ThreatScore", "Actor"]
    )


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
