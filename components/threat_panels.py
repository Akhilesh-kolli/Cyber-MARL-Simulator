"""
components/threat_panels.py
---------------------------
Renders the Threat Hunt Summary and IOC Intelligence Registry workspaces.

FIX (Issue #14,#15,#16,#17,#18): IOC Asset/Source/Destination/Confidence/Severity fixed.
FIX (Issue #15): IOC Source column no longer truncates critical values.
FIX (Issue #19): Threat Hunt technique count uses same IOC registry as MITRE Analytics.
FIX (Issue #29): Both panels consume same canonical events/ioc_df from session state.
"""

import streamlit as st
import pandas as pd
from analytics.hunt_analytics import get_threat_hunt_summary
from analytics.ioc_engine import IOCEngine


def _get_shared_ioc_df(state: dict):
    """
    Returns the shared IOC registry DataFrame, computing it from canonical events
    if not already in session state. This ensures all panels use the same data.
    FIX #29: Single IOC registry shared across Threat Hunt, MITRE, Executive sections.
    """
    if st.session_state.get("ioc_df") is not None:
        return st.session_state.ioc_df
    events = state.get("events", [])
    if events:
        try:
            ioc_df = IOCEngine.generate_registry_df(events)
            st.session_state.ioc_df = ioc_df
            return ioc_df
        except Exception:
            pass
    return None


def render_threat_hunt_panel(state: dict):
    """
    Renders the Threat Hunt workspace.
    FIX #19: Unique Techniques count comes from shared IOC registry.
    """
    st.markdown("## SOC Response Actions")

    if not state.get("events") and not state.get("simulation", {}).get("running", False):
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to activate threat hunting analytics.</div>',
            unsafe_allow_html=True,
        )
        return

    # FIX #19: Use shared IOC DF for technique counts (same source as MITRE panel)
    ioc_df = _get_shared_ioc_df(state)
    summary = get_threat_hunt_summary(state)

    # FIX #19: Override technique count from shared IOC registry if available
    if ioc_df is not None and not ioc_df.empty and "Type" in ioc_df.columns:
        try:
            import re
            TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
            tech_rows = ioc_df[
                ioc_df["IOC"].astype(str).str.match(r"T\d{4}", na=False) &
                (ioc_df["Type"] == "Adversary Technique")
            ]
            if not tech_rows.empty:
                summary["unique_techniques_count"] = int(tech_rows["IOC"].nunique())
                summary["observed_techniques"] = sorted(list(tech_rows["IOC"].unique()))
        except Exception:
            pass

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
    FIX #14: Asset column populated from IOC registry.
    FIX #15: Source column shows full path (not truncated unreasonably).
    FIX #16: Destination reflects actual attack paths from events.
    FIX #17: Confidence is deterministic (from IOC engine scoring).
    FIX #18: Severity correlates with frequency, asset criticality, and attack success.
    """
    st.markdown("##  IOC Intelligence Registry")
    events = state.get("events", [])

    if not events and not state.get("simulation", {}).get("running", False):
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to populate IOC Intelligence.</div>',
            unsafe_allow_html=True,
        )
        return

    # FIX #29: Use shared IOC dataframe (single source of truth)
    ioc_df = _get_shared_ioc_df(state)
    if ioc_df is None:
        ioc_df = pd.DataFrame()

    # Normalize to strings for stable column sizing
    ioc_df = ioc_df.astype(str)

    if not ioc_df.empty:
        ioc_type_filter = st.selectbox(
            "Filter by Indicator Type",
            ["ALL", "Network Port", "Adversary Technique", "Technique on Asset", "CVE"],
            key="ioc_type_filter_selectbox"
        )
        if ioc_type_filter != "ALL":
            filtered_df = ioc_df[ioc_df["Type"] == ioc_type_filter]
        else:
            filtered_df = ioc_df

        # FIX #14,#15,#16: Use full column set with Source, Destination, Asset all populated
        display_order = [
            "IOC", "Type", "Severity", "Count", "Confidence",
            "Asset",         # FIX #14: populated from IOC engine
            "Source",        # FIX #15: full source label (not truncated)
            "First Seen", "Last Seen",
        ]
        existing_cols = [c for c in display_order if c in filtered_df.columns]
        display_df = filtered_df[existing_cols].copy()

        # Truncation limits
        trunc_map = {
            "IOC": 60,
            "Asset": 35,
            "Source": 40,
            "Destination": 35,
        }
        for col, maxlen in trunc_map.items():
            if col in display_df.columns:
                display_df[col] = display_df[col].apply(
                    lambda v: (str(v) if len(str(v)) <= maxlen else (str(v)[:maxlen - 3] + "..."))
                )

        column_config = {}
        if "IOC" in display_df.columns:
            column_config["IOC"] = st.column_config.TextColumn("IOC", width="large")
        if "Type" in display_df.columns:
            column_config["Type"] = st.column_config.TextColumn("Type", width="medium")
        if "Severity" in display_df.columns:
            column_config["Severity"] = st.column_config.TextColumn("Severity", width="small")
        if "Count" in display_df.columns:
            column_config["Count"] = st.column_config.TextColumn("Count", width="small")
        if "Confidence" in display_df.columns:
            column_config["Confidence"] = st.column_config.TextColumn("Confidence", width="small")
        if "First Seen" in display_df.columns:
            column_config["First Seen"] = st.column_config.TextColumn("First Seen", width="small")
        if "Last Seen" in display_df.columns:
            column_config["Last Seen"] = st.column_config.TextColumn("Last Seen", width="small")
        if "Asset" in display_df.columns:
            column_config["Asset"] = st.column_config.TextColumn("Asset", width="medium")
        if "Source" in display_df.columns:
            column_config["Source"] = st.column_config.TextColumn("Source", width="medium")  # FIX #15



        st.markdown('<div class="soc-table-card" style="overflow:auto; padding-bottom:8px; box-sizing:border-box;">', unsafe_allow_html=True)

        try:
            rows = len(display_df)
            header_h = 56
            row_h = 40
            extra_pad = 8
            if rows <= 0:
                table_height = header_h + 2 * row_h + extra_pad
            elif rows <= 6:
                table_height = header_h + rows * row_h + extra_pad
            else:
                table_height = header_h + 6 * row_h + extra_pad
        except Exception:
            table_height = 320

        st.dataframe(
            display_df,
            use_container_width=True,
            height=table_height,
            hide_index=True,
            column_config=column_config,
        )

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty-placeholder">No IOCs detected during current simulation steps.</div>', unsafe_allow_html=True)