"""
components/mitre_panels.py
--------------------------
Renders the MITRE ATT&CK Analytics workspace.

FIX (Issue #19, #20, #21): MITRE counts derived from same IOC registry as Threat Hunt.
FIX (Issue #22): Assets Impacted column no longer shows "Clean" when IOCs exist.
FIX (Issue #20): Correlation table includes all techniques found in Threat Hunt.
"""

import streamlit as st
from analytics import build_mitre_table
from visualization.chart_builder import render_mitre_pie
import re
import pandas as pd


def render_mitre_panel(state: dict):
    """
    Renders the MITRE Analytics workspace.
    FIX #21: Technique counts come from IOC registry (single source of truth).
    FIX #22: Assets Impacted populated from IOC registry Asset field.
    FIX #20: Correlation table covers ALL techniques seen in IOC registry.
    """
    st.markdown("## 🎯 MITRE ATT&CK Analytics")

    metrics = state["metrics"]
    technique_counts = {}
    correlation_df = None
    tech_re = re.compile(r"(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)

    # FIX #21: Use the shared IOC registry session state (computed once from canonical events)
    # If ioc_df not yet set, compute it now from canonical events
    if st.session_state.get("ioc_df") is None and state.get("events"):
        try:
            from analytics.ioc_engine import IOCEngine
            st.session_state.ioc_df = IOCEngine.generate_registry_df(state["events"])
        except Exception:
            pass

    if st.session_state.get("ioc_df") is not None:
        try:
            ioc_df = st.session_state.ioc_df.copy()
            if not ioc_df.empty and "IOC" in ioc_df.columns:
                ioc_df["_IOC_STR"] = ioc_df["IOC"].astype(str).str.upper()

                def _extract_base(s):
                    m = tech_re.search(s)
                    return m.group(1).upper() if m else None

                ioc_df["BaseTech"] = ioc_df["_IOC_STR"].apply(_extract_base)
                # FIX #21: Only use base technique rows (Type == "Adversary Technique")
                tech_rows = ioc_df[
                    ioc_df["BaseTech"].notna() &
                    (ioc_df.get("Type", pd.Series(dtype=str)).str.contains("Adversary Technique", na=False) |
                     ioc_df["BaseTech"].str.match(r"T\d{4}$", na=False))
                ]

                if not tech_rows.empty:
                    # FIX #21: Aggregate Count from IOC registry rows (authoritative)
                    agg_counts = {}
                    for _, row in tech_rows.iterrows():
                        tech = row.get("BaseTech") or ""
                        if not tech:
                            continue
                        # Use Count from IOC registry (not re-counting from raw events)
                        count_val = int(row.get("Count", 1) or 1)
                        agg_counts[tech] = agg_counts.get(tech, 0) + count_val

                    technique_counts = agg_counts

                    # Build correlation table - FIX #20/#22: include all techniques, real assets
                    rows = []
                    for tech, cnt in technique_counts.items():
                        subset = tech_rows[tech_rows["BaseTech"] == tech]

                        # FIX #22: Get assets from IOC registry Asset column
                        assets = set()
                        if "Asset" in subset.columns:
                            for a_cell in subset["Asset"].astype(str).unique():
                                if a_cell and a_cell.strip() not in ("", "nan", "N/A"):
                                    # FIX #22: Split comma-separated assets
                                    for a in a_cell.split(","):
                                        a = a.strip()
                                        if a:
                                            assets.add(a)
                        if "Destination" in subset.columns:
                            for d in subset["Destination"].astype(str).unique():
                                if d and d.strip() not in ("", "nan", "N/A", "Clean", "SOC"):
                                    assets.add(d.strip())

                        # FIX #22: If no assets found but technique has successes, check state nodes
                        if not assets:
                            try:
                                from utils.constants import NODE_MAPPING
                                for ni, nd in state.get("nodes", {}).items():
                                    if tech in nd.get("techniques", []):
                                        asset_name = NODE_MAPPING.get(ni, f"Node-{ni}")
                                        assets.add(asset_name)
                            except Exception:
                                pass

                        assets_str = ", ".join(sorted(assets)) if assets else "Observed (no asset mapped)"

                        # Ports
                        ports = set()
                        if "Ports" in subset.columns:
                            for pcell in subset["Ports"].astype(str).unique():
                                if pcell and pcell not in ("", "nan"):
                                    for p in str(pcell).split(","):
                                        p = p.strip()
                                        if p and p != "nan":
                                            ports.add(p)
                        try:
                            ports_sorted = sorted(ports, key=lambda x: int(x))
                        except Exception:
                            ports_sorted = sorted(ports)
                        ports_str = ",".join(ports_sorted) if ports_sorted else ""

                        # FIX #20: Include severity from IOC registry
                        sev = ""
                        if "Severity" in subset.columns:
                            sev_vals = subset["Severity"].astype(str).unique()
                            severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                            sev = max(sev_vals, key=lambda s: severity_rank.get(s.upper(), 0)) if len(sev_vals) > 0 else ""

                        rows.append({
                            "Technique": tech,
                            "Count": int(cnt),
                            "Severity": sev,
                            "Assets Impacted": assets_str,
                            "Ports Observed": ports_str
                        })

                    correlation_df = pd.DataFrame(rows).sort_values("Count", ascending=False).reset_index(drop=True)
        except Exception as ex:
            st.warning(f"MITRE IOC sync error: {ex}")
            technique_counts = metrics.get("technique_counts", {})
    else:
        # Fallback: normalize metric-based technique counts
        raw = metrics.get("technique_counts", {})
        norm = {}
        for k, v in raw.items():
            if not k:
                continue
            m = tech_re.search(str(k))
            if m:
                t = m.group(1).upper()
                norm[t] = norm.get(t, 0) + int(v or 0)
        technique_counts = norm

    if not state.get("events") and not state.get("simulation", {}).get("running", False):
        st.markdown(
            '<div class="empty-placeholder">&#9654; Run the simulation to view MITRE ATT&CK analytics.</div>',
            unsafe_allow_html=True,
        )
        return

    # Prepare chart data: collapse to top-9 + Other when > 10
    technique_counts_for_chart = dict(technique_counts or {})
    if technique_counts_for_chart and len(technique_counts_for_chart) > 10:
        sorted_items = sorted(technique_counts_for_chart.items(), key=lambda x: x[1], reverse=True)
        top_items = sorted_items[:9]
        other_sum = sum([v for _, v in sorted_items[9:]])
        technique_counts_for_chart = {k: int(v) for k, v in top_items}
        if other_sum > 0:
            technique_counts_for_chart["Other"] = int(other_sum)

    if st.session_state.get("mitre_df") is not None:
        mitre_df = st.session_state.mitre_df
    else:
        mitre_df = build_mitre_table(technique_counts_for_chart)

    render_mitre_pie(technique_counts_for_chart)

    # FIX #20: Show all techniques in correlation table
    if correlation_df is not None and not correlation_df.empty:
        st.markdown("### ATT&CK Correlation")
        st.table(correlation_df)
    elif technique_counts:
        # Minimal fallback table
        st.markdown("### ATT&CK Correlation")
        st.table(pd.DataFrame(
            [{"Technique": k, "Count": v, "Severity": "", "Assets Impacted": "", "Ports Observed": ""}
             for k, v in sorted(technique_counts.items(), key=lambda x: -x[1])]
        ))
