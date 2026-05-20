"""
components/mitre_panels.py
--------------------------
Renders the MITRE ATT&CK Analytics workspace using decoupled visualization and analytics.
"""

import streamlit as st
from analytics import build_mitre_table
from visualization.chart_builder import render_mitre_pie

def render_mitre_panel(state: dict):
    """
    Renders the MITRE Analytics workspace.
    """
    st.markdown("## 🎯 MITRE ATT&CK Analytics")
    
    metrics = state["metrics"]
    technique_counts = metrics.get("technique_counts", {})
    
    # Check if simulation started
    if not state.get("events") and not state.get("simulation", {}).get("running", False):
        st.info("▶ Run the simulation to view MITRE ATT&CK analytics.")
        return
        
    mitre_df = build_mitre_table(technique_counts)
    st.dataframe(mitre_df, use_container_width=True)
    
    # Render Plotly donut chart
    render_mitre_pie(technique_counts)
