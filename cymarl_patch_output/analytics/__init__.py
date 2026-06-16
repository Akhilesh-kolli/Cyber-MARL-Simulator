"""
analytics/__init__.py
---------------------
Package init — re-exports all public analytics utilities.

FIX (Issue #19,#20,#21): build_mitre_table now derives from IOC registry.
FIX (Issue #29): All analytics sections consume the same canonical event list
  and the same IOC registry rather than independent calculations.
FIX (Issue #12): Timeline CVE column filters DEFENDER-ACTION values.
FIX (Issue #13): Timeline includes Source/Target columns.
"""

import re
import pandas as pd
import plotly.express as px

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
    FIX #12: CVE column no longer shows DEFENDER-ACTION.
    FIX #13: Source/Target columns populated from event source/destination.
    FIX #11: Target Node uses real asset names (not Mitigation Node N).
    """
    try:
        from utils.formatting import format_event_log
    except ImportError:
        try:
            from event_engine import format_event_log
        except ImportError:
            def format_event_log(e):
                return e.get("message", str(e))

    TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

    rows = []
    cumulative = 0.0
    for idx, e in enumerate(events):
        label = format_event_log(e)
        base_score = THREAT_NUMERIC.get(e.get("threat", e.get("severity", "LOW")), 0)
        cumulative += base_score * (1 + idx * 0.04)
        escalation_score = round(cumulative, 2)

        technique = e.get("technique") or e.get("mitre_name") or "N/A"
        # FIX #10: Filter out synthetic DEF: and DEFENSIVE-OPS from technique column
        # Show action label for defender rows instead
        if str(technique).startswith("DEF:") or technique == "DEFENSIVE-OPS":
            da = e.get("defender_action") or ""
            technique = f"[{da}]" if da else "[DEFENDER]"

        target_node = e.get("node") or e.get("target") or e.get("destination") or "Unknown"
        source_node = e.get("source") or "Attacker"

        # FIX #11: Remove "Mitigation Node N" from target names
        if "Mitigation Node" in str(target_node):
            try:
                from utils.constants import NODE_MAPPING
                n = int(str(target_node).split("Mitigation Node")[-1].strip())
                target_node = NODE_MAPPING.get(n, target_node)
            except Exception:
                pass

        # FIX #12: Replace DEFENDER-ACTION in CVE column with N/A
        cve_val = e.get("cve", "N/A")
        if str(cve_val).upper() in ("DEFENDER-ACTION", "NOT-APPLICABLE"):
            cve_val = "N/A"

        confidence = e.get("detection_confidence") if e.get("detection_confidence") is not None else e.get("confidence", 0)
        status = e.get("status", "unknown")
        summary = e.get("event_summary") or e.get("message", "")

        if not summary:
            actor = e.get("actor", "")
            kc = e.get("kill_chain", "").lower()
            if actor == "defender":
                dact = e.get("defender_action") or e.get("action") or ""
                if dact:
                    summary = f"Defender executed {str(dact).capitalize()} on {target_node}."
                else:
                    summary = f"Defender action executed against {target_node}."
            elif "recon" in kc:
                summary = f"Port scan detected against {target_node}."
            elif "discovery" in kc:
                summary = f"Network discovery activity observed on {target_node}."
            elif "initial" in kc:
                summary = f"{technique} attempt against {target_node}."
            elif "execution" in kc:
                summary = f"Suspicious service execution on {target_node}."
            elif "persistence" in kc:
                summary = f"Persistence behavior detected on {target_node}."
            elif "privilege" in kc:
                summary = f"Privilege escalation attempt detected on {target_node}."
            elif "lateral" in kc:
                summary = f"Lateral movement from {source_node} to {target_node}."
            elif "collection" in kc:
                summary = f"Data collection activity observed on {target_node}."
            elif "exfil" in kc:
                summary = f"Suspicious outbound transfer from {target_node}."
            elif "command" in kc:
                summary = f"C2 channel established via {source_node}."
            elif "mitigation" in kc:
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
            "CVE":         cve_val,   # FIX #12
            "Actor":       str(e.get("actor", "unknown")).capitalize(),
            "Confidence":  confidence,
            "Status":      status,
            "Event Summary": summary,
            "Event":       label,
            "Defender Action": e.get("defender_action") or "",
            "ThreatScore": escalation_score,
        }
        if "timeline_weight" in e:
            row["timeline_weight"] = e["timeline_weight"]
        rows.append(row)

    cols = [
        "Event ID", "Time", "Stage", "Severity", "Threat", "Technique",
        "Target Node", "Source Node", "CVE", "Actor", "Confidence",
        "Status", "Event Summary", "Event", "Defender Action", "ThreatScore"
    ]
    return pd.DataFrame(rows, columns=cols) if rows else pd.DataFrame(columns=cols)


# ---------------------------------------------------------------------------
# CHART DATAFRAME
# ---------------------------------------------------------------------------
def build_chart_df(
    step_history:       list,
    threat_history:     list,
    compromise_history: list,
    defense_history:    list = None,
    momentum_history:   list = None,
) -> pd.DataFrame:
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
# FIX #19/#21: Derives from IOC registry when available
# ---------------------------------------------------------------------------
def build_mitre_pie(technique_counts: dict, ioc_df=None):
    """
    Build a Plotly donut chart.
    FIX #21: When ioc_df is provided, technique counts come from IOC registry
    (authoritative) rather than the raw technique_counts accumulator.
    """
    # If IOC registry available, use it as authoritative source
    if ioc_df is not None and not ioc_df.empty and "Type" in ioc_df.columns:
        try:
            from analytics.mitre_mapper import get_mitre_frequencies_from_ioc_registry
            registry_counts = get_mitre_frequencies_from_ioc_registry(ioc_df)
            if registry_counts:
                technique_counts = registry_counts
        except Exception:
            pass

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
# FIX #21: Derives from IOC registry
# ---------------------------------------------------------------------------
def build_mitre_table(technique_counts: dict, ioc_df=None) -> pd.DataFrame:
    """
    FIX #21: When ioc_df is provided, derive counts from IOC registry.
    This ensures MITRE Analytics shows same techniques as IOC Registry and Threat Hunt.
    """
    if ioc_df is not None and not ioc_df.empty and "Type" in ioc_df.columns:
        try:
            from analytics.mitre_mapper import get_mitre_frequencies_from_ioc_registry
            registry_counts = get_mitre_frequencies_from_ioc_registry(ioc_df)
            if registry_counts:
                technique_counts = registry_counts
        except Exception:
            pass

    return (
        pd.DataFrame({
            "Technique": list(technique_counts.keys()),
            "Frequency": list(technique_counts.values()),
        })
        .sort_values("Frequency", ascending=False)
        .reset_index(drop=True)
    )


# ---------------------------------------------------------------------------
# ESCALATION TREND CHART
# ---------------------------------------------------------------------------
def build_escalation_chart(timeline_df: pd.DataFrame):
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
        legend=dict(orientation="h", yanchor="top", y=-0.2, xanchor="center", x=0.5, font=dict(size=10)),
        xaxis=dict(showgrid=True, gridcolor="#1e293b", title="Event"),
        yaxis=dict(showgrid=True, gridcolor="#1e293b", title="Cumulative Threat Score"),
        margin=dict(l=10, r=10, t=40, b=50),
        height=350
    )
    return fig


def filter_timeline(timeline_df: pd.DataFrame, threat_filter: str) -> pd.DataFrame:
    if threat_filter == "ALL" or timeline_df.empty:
        return timeline_df
    return timeline_df[timeline_df["Threat"] == threat_filter]


def export_soc_report(timeline_df: pd.DataFrame) -> bytes:
    return timeline_df.to_csv(index=False).encode("utf-8")
