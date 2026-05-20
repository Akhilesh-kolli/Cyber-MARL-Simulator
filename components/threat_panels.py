"""
components/threat_panels.py
---------------------------
Renders the Threat Hunt Summary and IOC Intelligence Registry workspaces.
"""

import streamlit as st
import pandas as pd
from analytics.hunt_analytics import get_threat_hunt_summary
from analytics.ioc_engine import IOCEngine

def render_threat_hunt_panel(state: dict):
    """
    Renders the Threat Hunt workspace.
    """
    st.markdown("## 🕵️ Threat Hunt Summary")
    
    # Check if simulation started
    if not state.get("events") and not state.get("simulation", {}).get("running", False):
        st.info("▶ Run the simulation to activate threat hunting analytics.")
        return

    summary = get_threat_hunt_summary(state)
    
    hunt_c1, hunt_c2, hunt_c3 = st.columns(3)
    hunt_c1.metric("Unique Techniques", summary["unique_techniques_count"])
    hunt_c2.metric("Observed Ports", summary["observed_ports_count"])
    hunt_c3.metric("Compromised Assets", summary["compromised_assets_count"])

    with st.expander("🔍 Threat Hunt Details", expanded=False, key="threat_hunt_details_expander"):
        det_c1, det_c2, det_c3 = st.columns(3)
        det_c1.metric("Alert Fatigue Score", f"{summary['alert_fatigue_score']:.1f}")
        det_c2.metric("Successful Defenses", summary["successful_defenses"])
        det_c3.metric("Failed Defenses", summary["failed_defenses"])

        st.markdown("#### 🎯 Observed MITRE Techniques")
        if summary["observed_techniques"]:
            tech_str = " · ".join(summary["observed_techniques"])
            st.markdown(f"`{tech_str}`")
        else:
            st.info("No techniques observed yet.")

        st.markdown("#### 📡 Attack Stages Observed")
        if summary["observed_stages"]:
            for stage in summary["observed_stages"]:
                st.markdown(f"- {stage}")
        else:
            st.info("No attack stages observed yet.")

        st.markdown("#### 🛡️ SOC Recommendation")
        st.markdown(
            f'<div style="background:#0d2136;border-left:4px solid #0ea5e9;'
            f'border-radius:8px;padding:14px 18px;color:#e2e8f0;font-size:1rem;'
            f'font-weight:600;margin-top:8px;">'
            f'🔒 {summary["soc_recommendation"]}'
            f'</div>',
            unsafe_allow_html=True
        )

def render_ioc_panel(state: dict):
    """
    Renders the IOC Intelligence Registry workspace.
    """
    st.markdown("## 🧠 IOC Intelligence Registry")
    events = state.get("events", [])
    
    if not events and not state.get("simulation", {}).get("running", False):
        st.info("▶ Run the simulation to populate IOC Intelligence.")
        return
        
    ioc_df = IOCEngine.generate_registry_df(events)
    if not ioc_df.empty:
        # Interactive Filter
        ioc_type_filter = st.selectbox(
            "Filter by Indicator Type",
            ["ALL", "Network Port", "Adversary Technique"],
            key="ioc_type_filter_selectbox"
        )
        if ioc_type_filter != "ALL":
            filtered_df = ioc_df[ioc_df["Type"] == ioc_type_filter]
        else:
            filtered_df = ioc_df
            
        st.dataframe(filtered_df, use_container_width=True)
    else:
        st.info("No IOCs detected during current simulation steps.")
