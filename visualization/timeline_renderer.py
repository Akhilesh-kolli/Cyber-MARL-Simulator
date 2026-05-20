"""
visualization/timeline_renderer.py
----------------------------------
Builds structured chronological timeline grids with severity-filtering
and export downloads.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import json
from analytics import build_timeline_df, filter_timeline, export_soc_report

class SOCJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

def render_timeline_section(state: dict):
    """
    Renders the complete Attack Timeline UI block inside the Overview workspace.
    Includes filtering dropdown, dataframes, inline trend plot, and CSV/JSON downloads.
    """
    metrics = state["metrics"]
    events = state["events"]
    
    st.markdown("## 📊 Attack Timeline")
    
    if not state.get("simulation", {}).get("running", False) and not events:
        st.info("▶ Run the simulation to populate the Attack Timeline.")
        return

    # Filter dropdown
    selected_threat = st.selectbox(
        "Filter Threat Level",
        ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        key="threat_filter"
    )

    # 1. Build DataFrame
    timeline_df = build_timeline_df(events)
    
    if not timeline_df.empty:
        # Sort if timeline_weight exists
        if "timeline_weight" in timeline_df.columns:
            timeline_df = timeline_df.sort_values(
                by="timeline_weight",
                ascending=False
            )
            
        # Apply filter
        filtered_df = filter_timeline(timeline_df, selected_threat)
        
        # Display DataFrame
        st.markdown("### 📋 Quick View (Top 10 Events)")
        st.dataframe(filtered_df.head(10), use_container_width=True)
        
        with st.expander("📋 View Full Filtered Timeline Log"):
            st.dataframe(filtered_df, use_container_width=True)
            
        # 2. Render plot
        if not filtered_df.empty:
            fig_trend = px.line(
                filtered_df.head(10),
                x="Time",
                y="ThreatScore",
                color="Stage",
                title="Threat Escalation Trend (Quick View)",
                markers=True
            )
            fig_trend.update_layout(
                paper_bgcolor="#071028",
                plot_bgcolor="#071028",
                font_color="white",
                xaxis=dict(showgrid=True, gridcolor="#1e293b"),
                yaxis=dict(showgrid=True, gridcolor="#1e293b"),
                margin=dict(l=20, r=20, t=50, b=20),
                height=350
            )
            st.plotly_chart(fig_trend, use_container_width=True, config={"responsive": True})
            
    # 3. Downloads
    if events:
        full_df = build_timeline_df(events)
        csv_data = export_soc_report(full_df)
        
        # Create a copy of the state excluding self-referential keys
        export_data = {}
        for k, v in state.items():
            if k == "metrics":
                export_data[k] = {mk: mv for mk, mv in v.items() if mk != "metrics"}
            else:
                export_data[k] = v
                
        json_data = json.dumps(export_data, cls=SOCJSONEncoder, indent=2)
        
        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button(
                label="📥 Download CSV SOC Report",
                data=csv_data,
                file_name="soc_attack_timeline.csv",
                mime="text/csv",
                key="download_soc_report"
            )
        with dl_col2:
            st.download_button(
                label="📥 Download JSON Telemetry",
                data=json_data,
                file_name="soc_telemetry_dump.json",
                mime="application/json",
                key="download_soc_json"
            )
