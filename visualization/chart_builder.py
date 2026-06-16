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
        st.markdown('<div class="empty-placeholder">No trend telemetry captured yet.</div>', unsafe_allow_html=True)
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
        autosize=True,
        paper_bgcolor="#071028",
        plot_bgcolor="#071028",
        font_color="white",
        xaxis=dict(showgrid=True, gridcolor="#1e293b"),
        yaxis=dict(showgrid=True, gridcolor="#1e293b"),
        margin=dict(l=10, r=10, t=40, b=10),
        height=350
    )
    
    st.plotly_chart(
        fig,
        use_container_width=True,
        config={"responsive": True},
        key="threat_trend_chart"
    )
    return fig

def render_mitre_pie(technique_counts: dict):
    """
    Renders a clean, responsive donut/pie chart representing the MITRE ATT&CK distribution.
    """
    active = {k: v for k, v in technique_counts.items() if v > 0}
    if not active:
        st.markdown('<div class="empty-placeholder">No adversary techniques observed during current simulation steps.</div>', unsafe_allow_html=True)
        return None

    # If only a single technique was observed, show an explanatory message
    # instead of a misleading 100% donut chart.
    if len(active) == 1:
        tname, tfreq = list(active.items())[0]
        st.markdown(
            f'<div class="empty-placeholder">Only one ATT&CK technique was observed during this simulation. Additional technique diversity is required for meaningful ATT&CK distribution analysis.<br><strong>Observed:</strong> {tname} ({tfreq} occurrences)</div>',
            unsafe_allow_html=True,
        )
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
    
    st.plotly_chart(
        fig,
        use_container_width=True,
        config={"responsive": True},
        key="mitre_pie_chart"
    )
    return fig

def render_escalation_chart(timeline_df: pd.DataFrame):
    """
    Renders the sequential threat escalation curve.
    """
    if timeline_df.empty:
        st.markdown('<div class="empty-placeholder">Awaiting campaign progression to map escalation trends.</div>', unsafe_allow_html=True)
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
        xaxis=dict(showgrid=True, gridcolor="#1e293b", title="Event Index"),
        yaxis=dict(showgrid=True, gridcolor="#1e293b", title="Threat Score"),
        margin=dict(l=10, r=10, t=40, b=50),
        height=350
    )
    
    st.plotly_chart(
        fig,
        use_container_width=True,
        config={"responsive": True},
        key="escalation_chart"
    )
    return fig
