"""
visualization/chart_builder.py
------------------------------
Decouples Plotly line charts, donuts, and threat trends with uniform styles.
"""

import plotly.express as px
import pandas as pd
import streamlit as st
from analytics import build_chart_df

def render_threat_trend_chart(
    step_history: list,
    threat_history: list,
    compromise_history: list,
    defense_history: list = None,
    momentum_history: list = None
):
    """
    Renders a unified line chart showing threat metrics over steps.
    """
    df = build_chart_df(
        step_history,
        threat_history,
        compromise_history,
        defense_history,
        momentum_history
    )
    
    if df.empty:
        st.info("No trend telemetry captured yet.")
        return None

    # Melt the dataframe for multi-line Plotly express
    value_vars = ["Critical Alerts", "Compromised Nodes"]
    if "Successful Defenses" in df.columns:
        value_vars.append("Successful Defenses")
    if "Threat Momentum" in df.columns:
        value_vars.append("Threat Momentum")
        
    df_melt = df.melt(
        id_vars=["Step"],
        value_vars=value_vars,
        var_name="Metric",
        value_name="Value"
    )
    
    fig = px.line(
        df_melt,
        x="Step",
        y="Value",
        color="Metric",
        title="Simulation Telemetry Trends",
        markers=True,
        color_discrete_map={
            "Critical Alerts": "#ef4444",      # Red
            "Compromised Nodes": "#eab308",    # Yellow
            "Successful Defenses": "#22c55e",  # Green
            "Threat Momentum": "#0ea5e9"       # Blue
        }
    )
    
    fig.update_layout(
        paper_bgcolor="#071028",
        plot_bgcolor="#071028",
        font_color="white",
        xaxis=dict(showgrid=True, gridcolor="#1e293b"),
        yaxis=dict(showgrid=True, gridcolor="#1e293b"),
        margin=dict(l=20, r=20, t=50, b=20),
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True, config={"responsive": True})
    return fig

def render_mitre_pie(technique_counts: dict):
    """
    Renders a clean, responsive donut/pie chart representing the MITRE ATT&CK distribution.
    """
    active = {k: v for k, v in technique_counts.items() if v > 0}
    if not active:
        st.info("No adversary techniques observed during current simulation steps.")
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
        hole=0.45,
    )
    
    fig.update_layout(
        paper_bgcolor="#071028",
        plot_bgcolor="#071028",
        font_color="white",
        margin=dict(l=20, r=20, t=50, b=20),
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True, config={"responsive": True})
    return fig

def render_escalation_chart(timeline_df: pd.DataFrame):
    """
    Renders the sequential threat escalation curve.
    """
    if timeline_df.empty:
        st.info("Awaiting campaign progression to map escalation trends.")
        return None

    fig = px.line(
        timeline_df.head(25),
        x="Time",
        y="ThreatScore",
        color="Stage",
        title="Threat Escalation Trend (Last 25 Events)",
        markers=True,
        color_discrete_sequence=px.colors.qualitative.Safe
    )
    
    fig.update_layout(
        paper_bgcolor="#071028",
        plot_bgcolor="#071028",
        font_color="white",
        xaxis=dict(showgrid=True, gridcolor="#1e293b"),
        yaxis=dict(showgrid=True, gridcolor="#1e293b"),
        margin=dict(l=20, r=20, t=50, b=20),
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True, config={"responsive": True})
    return fig
