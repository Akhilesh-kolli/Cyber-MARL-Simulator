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
    st.markdown("## SOC Response Actions")
    
    # Check if simulation started
    if not state.get("events") and not state.get("simulation", {}).get("running", False):
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to activate threat hunting analytics.</div>',
            unsafe_allow_html=True,
        )
        return

    summary = get_threat_hunt_summary(state)
    
    hunt_c1, hunt_c2, hunt_c3 = st.columns(3)
    hunt_c1.metric("Unique Techniques", summary["unique_techniques_count"])
    hunt_c2.metric("Observed Ports", summary["observed_ports_count"])
    hunt_c3.metric("Compromised Assets", summary["compromised_assets_count"])

    with st.expander(" Threat Hunt Details", expanded=False, key="threat_hunt_details_expander"):
        det_c1, det_c2, det_c3 = st.columns(3)
        det_c1.metric("Alert Fatigue Score", f"{summary['alert_fatigue_score']:.1f}")
        det_c2.metric("Successful Defenses", summary["successful_defenses"])
        det_c3.metric("Failed Defenses", summary["failed_defenses"])

        st.markdown("####  Observed MITRE Techniques")
        if summary["observed_techniques"]:
            tech_cols = st.columns(2)
            tech_list = [f'`{t}`' for t in summary["observed_techniques"]]
            with tech_cols[0]:
                st.markdown("\n".join(tech_list[0::2]))
            with tech_cols[1]:
                st.markdown("\n".join(tech_list[1::2]))
        else:
            st.markdown('<div class="empty-placeholder">No techniques observed yet.</div>', unsafe_allow_html=True)

        st.markdown("#### Attack Stages Observed")
        if summary["observed_stages"]:
            stage_cols = st.columns(2)
            for idx, stage in enumerate(summary["observed_stages"]):
                with stage_cols[idx % 2]:
                    st.markdown(f"- {stage}")
        else:
            st.markdown('<div class="empty-placeholder">No attack stages observed yet.</div>', unsafe_allow_html=True)

        st.markdown("#### Tactical Response Actions")
        if summary.get("tactical_actions"):
            action_cols = st.columns(2)
            for idx, action in enumerate(summary["tactical_actions"]):
                with action_cols[idx % 2]:
                    st.markdown(f"- {action}")
        else:
            st.markdown('<div class="empty-placeholder">No tactical response actions identified yet.</div>', unsafe_allow_html=True)

def render_ioc_panel(state: dict):
    """
    Renders the IOC Intelligence Registry workspace.
    """
    st.markdown("##  IOC Intelligence Registry")
    events = state.get("events", [])
    
    if not events and not state.get("simulation", {}).get("running", False):
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to populate IOC Intelligence.</div>',
            unsafe_allow_html=True,
        )
        return
        
    # Prefer persisted IOC dataframe after simulation to avoid rerender loss
    if st.session_state.get("ioc_df") is not None:
        ioc_df = st.session_state.ioc_df
    else:
        ioc_df = IOCEngine.generate_registry_df(events)

    # Normalize to strings for stable column sizing and rendering
    ioc_df = ioc_df.astype(str)

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

        column_config = {
            "IOC": st.column_config.TextColumn("IOC", width="large"),
            "Type": st.column_config.TextColumn("Type", width="medium"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "First Seen": st.column_config.TextColumn("First Seen", width="small"),
            "Count": st.column_config.TextColumn("Count", width="small"),
            "Confidence": st.column_config.TextColumn("Confidence", width="small"),
        }

        # Clean SOC table card without duplicate separators
        st.markdown(
            
            '<div class="soc-table-card">',
            unsafe_allow_html=True
        )

        st.dataframe(
            filtered_df,
            use_container_width=True,
            height=520,
            hide_index=True,
            column_config=column_config,
        )

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty-placeholder">No IOCs detected during current simulation steps.</div>', unsafe_allow_html=True)
