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
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to view MITRE ATT&CK analytics.</div>',
            unsafe_allow_html=True,
        )
        return
        
    # Prefer persisted dataframe after simulation to avoid rerender loss
    if st.session_state.get("mitre_df") is not None:
        mitre_df = st.session_state.mitre_df
    else:
        mitre_df = build_mitre_table(technique_counts)

    # Render Plotly donut chart only (table removed for cleaner UX)
    render_mitre_pie(technique_counts)
