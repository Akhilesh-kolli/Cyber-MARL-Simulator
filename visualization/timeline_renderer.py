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


def _safe_serialize(obj, _seen=None):
    """Recursively serialize common Python objects while detecting circular refs.

    Returns a JSON-serializable structure with circular references replaced
    by the string "<circular>".
    """
    if _seen is None:
        _seen = set()
    oid = id(obj)
    if oid in _seen:
        return "<circular>"

    # primitives
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # sequences
    if isinstance(obj, (list, tuple, set)):
        _seen.add(oid)
        res = [_safe_serialize(v, _seen) for v in obj]
        _seen.discard(oid)
        return res

    # dict
    if isinstance(obj, dict):
        _seen.add(oid)
        out = {}
        for k, v in obj.items():
            try:
                key = str(k)
            except Exception:
                key = "<key>"
            out[key] = _safe_serialize(v, _seen)
        _seen.discard(oid)
        return out

    # pandas / numpy
    try:
        import pandas as _pd
        import numpy as _np
        if _pd and isinstance(obj, _pd.DataFrame):
            return obj.to_dict(orient="records")
        if _pd and isinstance(obj, _pd.Series):
            return obj.tolist()
        if _np and isinstance(obj, _np.ndarray):
            return obj.tolist()
    except Exception:
        pass

    # bytes
    if isinstance(obj, (bytes, bytearray)):
        try:
            import base64
            return base64.b64encode(bytes(obj)).decode("ascii")
        except Exception:
            return "<binary>"

    # datetime
    try:
        from datetime import datetime as _dt
        if isinstance(obj, _dt):
            return obj.isoformat()
    except Exception:
        pass

    # fallback to string
    try:
        return str(obj)
    except Exception:
        return "<unserializable>"


def render_clean_timeline_section(state: dict):
    """Render the Threat Hunt timeline without extra filter controls."""
    events = state.get("events", [])
    st.markdown("<h2>Attack Timeline Log</h2>", unsafe_allow_html=True)

    if not state.get("simulation", {}).get("running", False) and not events:
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to populate the Attack Timeline.</div>',
            unsafe_allow_html=True,
        )
        return

    if st.session_state.get("attack_df") is not None:
        timeline_df = st.session_state.attack_df
    else:
        timeline_df = build_timeline_df(events)

    if timeline_df.empty:
        st.markdown(
            '<div class="empty-placeholder">&#9654; Attack timeline will appear once events are generated.</div>',
            unsafe_allow_html=True,
        )
        return

    # Build display columns and include 'Frequency' when present
    display_columns = [
        "Event ID", "Time", "Stage", "Severity", "Technique", "Target Node",
        "Source Node", "CVE", "Actor", "Confidence", "Status"
    ]
    if "Frequency" in timeline_df.columns:
        # insert Frequency after Technique for better readability
        insert_at = display_columns.index("Technique") + 1
        display_columns.insert(insert_at, "Frequency")
    display_df = timeline_df.loc[:, [c for c in display_columns if c in timeline_df.columns]].reset_index(drop=True)

    st.markdown('<div class="soc-card"><div class="soc-table-wrapper">', unsafe_allow_html=True)
    st.dataframe(display_df, use_container_width=False, width=1200, height=520, hide_index=True)
    st.markdown('</div></div>', unsafe_allow_html=True)

    csv_data = export_soc_report(timeline_df)
    # Serialize a safe, JSON-serializable snapshot of the canonical `state`
    json_data = json.dumps(_safe_serialize(state), indent=2)
    dl_col1, dl_col2 = st.columns(2)
    with dl_col1:
        st.download_button(
            label="Download CSV SOC Report",
            data=csv_data,
            file_name="soc_attack_timeline.csv",
            mime="text/csv",
            key="download_soc_report_button",
        )
    with dl_col2:
        st.download_button(
            label="Download JSON Telemetry",
            data=json_data,
            file_name="soc_telemetry_dump.json",
            mime="application/json",
            key="download_soc_json_button",
        )

def render_timeline_section(state: dict):
    """
    Renders the complete Attack Timeline UI block inside the Overview workspace.
    Includes filtering dropdown, dataframe, inline trend plot, and CSV/JSON downloads.
    """
    metrics = state["metrics"]
    events = state["events"]
    
    st.markdown("## 📊 Attack Timeline")
    
    # If no live events and not running, show a titled placeholder
    if not state.get("simulation", {}).get("running", False) and not events:
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to populate the Attack Timeline.</div>',
            unsafe_allow_html=True,
        )
        return

    # Filter dropdown
    selected_threat = st.selectbox(
        "Filter Threat Level",
        ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        key="threat_filter_selectbox"
    )

    # 1. Build DataFrame (prefer persisted dataframe after simulation)
    if st.session_state.get("attack_df") is not None:
        timeline_df = st.session_state.attack_df
    else:
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
        
        # Display DataFrame (exactly once, no double tables/expanders)
        st.markdown("### 📋 Attack Timeline Log")
        # Build display columns and include 'Frequency' when present
        display_columns = [
            "Event ID", "Time", "Stage", "Severity", "Technique", "Target Node",
            "Source Node", "CVE", "Actor", "Confidence", "Status"
        ]
        if "Frequency" in filtered_df.columns:
            insert_at = display_columns.index("Technique") + 1
            display_columns.insert(insert_at, "Frequency")
        display_df = filtered_df.loc[:, [c for c in display_columns if c in filtered_df.columns]].reset_index(drop=True)
        # Wrap in a single horizontal-scroll wrapper; use a fixed width so the
        # table gets a horizontal scrollbar instead of stretching the layout.
        st.markdown('<div class="soc-card"><div class="soc-table-wrapper">', unsafe_allow_html=True)
        st.dataframe(display_df, use_container_width=False, width=1200, height=520, hide_index=True)
        st.markdown('</div></div>', unsafe_allow_html=True)
            
        # 2. Render plot
        if not filtered_df.empty:
            # Build a single continuous cumulative escalation line sorted chronologically
            plot_df = filtered_df.sort_values(by=["Event ID", "Time"]).reset_index(drop=True)
            if "ThreatScore" not in plot_df.columns:
                plot_df["ThreatScore"] = 0
            plot_df["CumulativeThreat"] = plot_df["ThreatScore"].cumsum()
            plot_df["EventIndex"] = range(1, len(plot_df) + 1)
            fig_trend = px.line(
                plot_df,
                x="EventIndex",
                y="CumulativeThreat",
                title="Threat Escalation Trend (Cumulative)",
                markers=False,
                color_discrete_sequence=["#ff6b6b"],
            )
            fig_trend.update_layout(
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
                xaxis=dict(showgrid=True, gridcolor="#1e293b", title="Event #"),
                yaxis=dict(showgrid=True, gridcolor="#1e293b", title="Cumulative Threat Score"),
                margin=dict(l=10, r=10, t=40, b=50),
                height=350,
            )
            st.plotly_chart(
                fig_trend,
                use_container_width=True,
                config={"responsive": True},
                key="timeline_threat_escalation_trend"
            )
            
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
                
        # Use the safe serializer to avoid circular reference errors
        json_data = json.dumps(_safe_serialize(export_data), indent=2)
        
        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button(
                label="📥 Download CSV SOC Report",
                data=csv_data,
                file_name="soc_attack_timeline.csv",
                mime="text/csv",
                key="download_soc_report_button"
            )
        with dl_col2:
            st.download_button(
                label="📥 Download JSON Telemetry",
                data=json_data,
                file_name="soc_telemetry_dump.json",
                mime="application/json",
                key="download_soc_json_button"
            )
