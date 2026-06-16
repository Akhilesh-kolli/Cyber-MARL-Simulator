"""
exports/pdf_exporter.py
-----------------------
Responsible for generating an in-memory Executive SOC Incident Report PDF
using ReportLab. Produces a bytes object suitable for Streamlit's
`st.download_button` without writing any temporary files.
"""
# Defer importing reportlab until runtime inside functions so the app can
# import/exporter module even if reportlab is not installed. This avoids
# crashing the entire Streamlit app on environments without the optional
# dependency. reportlab is only required when actually generating PDFs.
import io
from datetime import datetime

try:
    import pandas as pd
except Exception:
    pd = None


def _df_to_table_data(df, max_rows=30, columns=None):
    """Convert a pandas DataFrame (or list-of-dicts) to ReportLab table data.

    Truncates to `max_rows` rows to keep pages readable.
    """
    if df is None:
        return []

    # Accept list-of-dicts as well
    try:
        if pd is not None and isinstance(df, pd.DataFrame):
            table_df = df.copy()
        else:
            # try to coerce to DataFrame if pandas available
            if pd is not None:
                table_df = pd.DataFrame(df)
            else:
                # fall back to basic list handling
                if isinstance(df, list) and len(df) > 0 and isinstance(df[0], dict):
                    headers = list(df[0].keys())
                    data = [headers]
                    for r in df[:max_rows]:
                        data.append([str(r.get(h, "")) for h in headers])
                    return data
                return []
    except Exception:
        return []

    if columns:
        cols = [c for c in columns if c in table_df.columns]
    else:
        cols = list(table_df.columns)

    data = [cols]
    for _, row in table_df.head(max_rows).iterrows():
        data.append([str(row.get(c, "")) for c in cols])
    return data


def _styled_table(data, col_widths=None, font_size=8):
    # Import reportlab primitives lazily so importing this module doesn't
    # require the optional dependency to be installed.
    try:
        from reportlab.platypus import Table, TableStyle
        from reportlab.lib import colors
    except Exception:
        raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab")

    if not data:
        return None
    t = Table(data, colWidths=col_widths)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ])
    t.setStyle(style)
    return t


def generate_soc_pdf_report(
    soc_metrics: dict,
    sidebar_summary: dict,
    attack_timeline_df,
    mitre_df,
    ioc_df,
    live_feed: list,
) -> bytes:
    """Generate an Executive SOC Incident Report PDF and return bytes.

    All inputs are consumed read-only. The function performs reasonable
    truncation for wide/tall tables to avoid overly long pages.
    """
    # FIX #30: Re-derive MITRE technique counts from IOC registry when available.
    # This ensures PDF report matches the dashboard MITRE panel.
    if ioc_df is not None:
        try:
            import pandas as _pd_fix
            if isinstance(ioc_df, _pd_fix.DataFrame) and not ioc_df.empty and "Type" in ioc_df.columns:
                import re as _re_fix
                _TECH_RE = _re_fix.compile(r"T\d{4}(?:\.\d{3})?", _re_fix.IGNORECASE)
                _tech_rows = ioc_df[
                    ioc_df["Type"].astype(str).str.contains("Adversary Technique", na=False) &
                    ioc_df["IOC"].astype(str).str.match(r"T\d{4}", na=False)
                ]
                if not _tech_rows.empty and "Count" in _tech_rows.columns:
                    _ioc_counts = {}
                    for _, _r in _tech_rows.iterrows():
                        _tech_key = str(_r["IOC"]).strip().upper()
                        _cnt = int(_r.get("Count", 1) or 1)
                        _ioc_counts[_tech_key] = _ioc_counts.get(_tech_key, 0) + _cnt
                    if _ioc_counts:
                        # Override mitre_df with IOC-registry-derived counts
                        mitre_df = _pd_fix.DataFrame({
                            "Technique": list(_ioc_counts.keys()),
                            "Frequency": list(_ioc_counts.values()),
                        }).sort_values("Frequency", ascending=False).reset_index(drop=True)
        except Exception:
            pass  # fall through to original mitre_df handling

    # Lazy-import reportlab and plotly at runtime to avoid import-time crashes
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            PageBreak,
            Image as RLImage,
            Table,
            TableStyle,
            KeepTogether,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except Exception as e:
        raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab") from e

    # Try to import plotly/kaleido for image exports; if unavailable we'll skip charts
    try:
        import plotly.graph_objects as go
        import plotly.express as px
    except Exception:
        go = None
        px = None

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()
    # Custom paragraph styles
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        alignment=1,
        spaceAfter=8,
    )
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, leading=16, spaceAfter=6)
    normal = ParagraphStyle("normal", parent=styles["Normal"], fontSize=10, leading=12)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=10)
    bullet = ParagraphStyle("bullet", parent=styles["Normal"], leftIndent=12, bulletIndent=6, bulletFontSize=9)

    content_width = letter[0] - doc.leftMargin - doc.rightMargin

    # Helper: map compromised asset ids to friendly labels
    def _map_asset_label(a: str) -> str:
        if not a:
            return "Unknown"
        s = str(a).lower()
        mapping = {
            "firewall": "Firewall / DVWA",
            "dvwa": "Firewall / DVWA",
            "kali": "Firewall / DVWA",
            "database": "Database",
            "db": "Database",
            "domaincontroller": "DomainController",
            "domain": "DomainController",
            "dc": "DomainController",
            "workstation": "Workstation",
            "host": "Workstation",
            "soc": "SOC",
        }
        for k, v in mapping.items():
            if k in s:
                return v
        # fallback: prettify
        return str(a)

    # Helper: export a plotly figure to PNG bytes in-memory
    def _plotly_to_png_bytes(fig, width: int = 800, height: int = 450) -> io.BytesIO:
        bio = io.BytesIO()
        if fig is None or (go is None and px is None):
            return None
        # Debug: log figure type and basic attributes to help diagnose export failures
        try:
            try:
                fig_repr = repr(fig)
            except Exception:
                fig_repr = str(type(fig))
            print("[pdf_exporter] Attempting to export Plotly figure. type=", type(fig), "has_to_image=", hasattr(fig, "to_image"))
            # limit repr length
            if fig_repr:
                print("[pdf_exporter] fig repr:", fig_repr[:1000])
            try:
                import streamlit as _st

                try:
                    print("[pdf_exporter] streamlit session keys:", list(_st.session_state.keys()))
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass

        # Try with Kaleido first, then fall back to a plain to_image call.
        try:
            try:
                img_bytes = fig.to_image(format="png", engine="kaleido", width=width, height=height, scale=2)
            except Exception as e_k:
                try:
                    img_bytes = fig.to_image(format="png", width=width, height=height, scale=2)
                except Exception as e_plain:
                    # Log both exceptions for diagnostic purposes and return None
                    try:
                        import traceback

                        print("Plotly image export failed (kaleido):", e_k)
                        traceback.print_exc()
                        print("Plotly image export failed (no-engine):", e_plain)
                        traceback.print_exc()
                    except Exception:
                        pass
                    return None

            bio.write(img_bytes)
            bio.seek(0)
            return bio
        except Exception as e:
            try:
                import traceback

                print("Unexpected error exporting Plotly figure to PNG:", e)
                traceback.print_exc()
            except Exception:
                pass
            return None

    # Helper: wrap text or list into a Paragraph (with bullets for lists)
    def _to_paragraph(cell, style=normal, max_chars=400):
        if cell is None:
            return Paragraph("", style)
        # If a string contains a Python literal list/dict, try to parse it
        if isinstance(cell, str):
            s = cell.strip()
            if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
                try:
                    import ast

                    lit = ast.literal_eval(s)
                    if isinstance(lit, (list, tuple, set)):
                        return _to_paragraph(list(lit), style=style, max_chars=max_chars)
                    if isinstance(lit, dict):
                        return _to_paragraph(lit, style=style, max_chars=max_chars)
                except Exception:
                    pass
        # Lists / tuples / sets -> bullet list (typographic bullet)
        if isinstance(cell, (list, tuple, set)):
            items = []
            for it in list(cell):
                s = str(it).strip()
                if len(s) > 200:
                    s = s[:200] + "..."
                items.append(f"• {s}")
            txt = "<br/>".join(items)
            return Paragraph(txt, style)
        # dict -> key: value per line
        if isinstance(cell, dict):
            items = [f"{k}: {v}" for k, v in cell.items()]
            txt = "<br/>".join(items)
            return Paragraph(txt, style)
        # string-like fallback
        s = str(cell)
        if len(s) > max_chars:
            s = s[: max_chars - 3] + "..."
        s = s.replace("\n", "<br/>")
        return Paragraph(s, style)

    # Helper: severity color
    def _severity_color(seg: str):
        if not seg:
            return colors.HexColor("#ffffff")
        s = str(seg).lower()
        if "critical" in s:
            return colors.HexColor("#b91c1c")
        if "high" in s:
            return colors.HexColor("#f97316")
        if "medium" in s:
            return colors.HexColor("#f59e0b")
        if "low" in s:
            return colors.HexColor("#facc15")
        return colors.white

    # Helper: robust 'has data' check for DataFrame/list/dict
    def _has_data(obj) -> bool:
        if obj is None:
            return False
        if pd is not None and isinstance(obj, pd.DataFrame):
            return not obj.empty
        if isinstance(obj, (list, tuple, set)):
            return len(obj) > 0
        if isinstance(obj, dict):
            return bool(obj)
        return True

    # Helper: coerce many input shapes into a stable list of values
    def _ensure_list(obj):
        if obj is None:
            return []
        # pandas Series
        try:
            if pd is not None and isinstance(obj, pd.Series):
                return list(obj.dropna().tolist())
        except Exception:
            pass
        if isinstance(obj, (list, tuple)):
            return list(obj)
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, dict):
            # prefer explicit list values when mapping-like
            vals = list(obj.values())
            if vals:
                return vals
            return list(obj.keys())
        if isinstance(obj, str):
            s = obj.strip()
            # try to parse Python literal lists/dicts safely
            if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
                try:
                    import ast

                    lit = ast.literal_eval(s)
                    if isinstance(lit, (list, tuple, set)):
                        return list(lit)
                    if isinstance(lit, dict):
                        return list(lit.values()) or list(lit.keys())
                except Exception:
                    pass
            # comma-separated fallback
            if "," in s:
                return [p.strip() for p in s.split(",") if p.strip()]
            return [s]
        # fall back to attempting iteration
        try:
            return list(obj)
        except Exception:
            return [str(obj)]

    # Helper: clean cell text for tables
    def _clean_cell_text(val):
        if val is None:
            return ""
        s = str(val).strip()
        if not s:
            return ""
        up = s.upper()
        if up == "NOT-APPLICABLE":
            return "N/A"
        if up in ("DEFENDER-ACTION", "DEFENDER_ACTION"):
            return "Defender Action"
        # collapse whitespace and underscores
        s = s.replace("_", " ")
        s = " ".join(s.split())
        return s

    # Header/footer drawing
    def _header_footer(canvas, doc):
        canvas.saveState()
        # Compact header
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(colors.HexColor("#0b1220"))
        header_y = doc.pagesize[1] - 0.36 * inch
        canvas.drawString(doc.leftMargin, header_y, "CYBER MARL SUMMARY REPORT")
        # subtle separator
        canvas.setStrokeColor(colors.HexColor("#dfe6ee"))
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, header_y - 4, doc.leftMargin + content_width, header_y - 4)
        # Footer: timestamp + page number (compact)
        footer_ts = datetime.utcnow().strftime("Generated: %Y-%m-%d %H:%M:%SZ")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(doc.leftMargin, 0.45 * inch - 6, footer_ts)
        page_str = f"Page {canvas.getPageNumber()}"
        canvas.drawRightString(doc.leftMargin + content_width, 0.45 * inch - 6, page_str)
        canvas.restoreState()

    story = []

    # ------------------ Page 1: Executive Summary ------------------
    story.append(Paragraph("CYBER MARL SUMMARY REPORT", title_style))
    # NOTE: per executive request, do not print a timestamp under the main title;
    # keep timestamp only in the footer/header to maximize first-page space.
    story.append(Spacer(1, 8))

    incident_status = (soc_metrics or {}).get("incident_status") or (sidebar_summary or {}).get("status", "N/A")
    threat_level = (soc_metrics or {}).get("threat_level") or (sidebar_summary or {}).get("threat", "N/A")
    risk_score = (soc_metrics or {}).get("risk_score") or (sidebar_summary or {}).get("risk", 0.0)
    compromised_assets = (soc_metrics or {}).get("compromised_assets") or []
    if isinstance(compromised_assets, set):
        compromised_assets = sorted(list(compromised_assets)) if compromised_assets else []
    defense_eff = (soc_metrics or {}).get("defense_effectiveness") or "N/A"
    soc_reco = (soc_metrics or {}).get("soc_recommendation") or "N/A"

    # Metrics table (two columns)
    metrics_data = [
        [Paragraph("<b>Incident Status</b>", normal), Paragraph(str(incident_status), normal)],
        [Paragraph("<b>Threat Level</b>", normal), Paragraph(str(threat_level), normal)],
        [Paragraph("<b>Risk Score</b>", normal), Paragraph(str(risk_score), normal)],
        [Paragraph("<b>Defense Effectiveness</b>", normal), Paragraph(str(defense_eff), normal)],
    ]
    mt = Table(metrics_data, colWidths=[2.5 * inch, content_width - 2.5 * inch])
    mt.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BOX", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    story.append(mt)
    story.append(Spacer(1, 8))

    # Compromised assets: coerce into a stable list, map and render as bullets
    compromised_list = _ensure_list(compromised_assets)
    mapped = [_map_asset_label(a) for a in compromised_list] if compromised_list else []
    story.append(Paragraph("<b>Compromised Assets</b>", normal))
    if mapped:
        story.append(_to_paragraph(mapped, style=normal))
    else:
        story.append(Paragraph("None", normal))

    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>SOC Recommendation</b>", normal))
    story.append(_to_paragraph(soc_reco, style=normal))
    # continue flow on the same page to improve space utilization

    # ------------------ Page 2: Network Topology + analysis ------------------
    story.append(Paragraph("Network Topology", h2))
    # Try to fetch plotly figures from session_state (if Streamlit is available)
    network_fig = None
    soc_trend_fig = None
    try:
        import streamlit as st

        network_fig = st.session_state.get("network_graph_fig")
        soc_trend_fig = st.session_state.get("soc_trend_fig")
    except Exception:
        # streamlit not available or no session state — skip
        network_fig = network_fig or None
        soc_trend_fig = soc_trend_fig or None

    if network_fig is not None and (go is not None or px is not None):
        img_bio = _plotly_to_png_bytes(network_fig, width=900, height=450)
        if img_bio:
            story.append(RLImage(img_bio, width=content_width * 0.95, height=content_width * 0.95 * 0.45))
        else:
            story.append(Paragraph("Network topology visual could not be embedded. View the interactive topology in the dashboard for full detail.", normal))
    else:
        story.append(Paragraph("Network topology visual not available for embedding. View the interactive topology in the dashboard.", normal))

    # Add short analysis (auto-generated)
    def _make_chart_commentary(metrics: dict, chart: str):
        # Return plain strings (no prefixed labels) to avoid duplication
        if chart == "network":
            cnt = len(_ensure_list((metrics or {}).get("compromised_assets", []))) if metrics else 0
            obs = f"{cnt} compromised node(s) observed in the current incident."
            analysis = "Lateral movement indicators suggest the attacker traversed exposed hosts."
            reco = "Isolate critical infrastructure (DomainController, DVWA, MySQL) immediately."
        elif chart == "soc_trend":
            obs = "Observed upward trend in event counts over the monitoring window."
            analysis = "SOC trending indicates increased attack surface activity; correlate with IOCs."
            reco = "Increase monitoring, tune detections, and validate containment for suspect hosts."
        else:
            obs = "Chart summary unavailable."
            analysis = "No additional analysis available."
            reco = "No recommendation available."
        return obs, analysis, reco

    obs, analysis, reco = _make_chart_commentary(soc_metrics or {}, "network")
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>Observation</b>", normal))
    story.append(Paragraph(obs, normal))
    story.append(Paragraph(f"<b>SOC Analysis</b>", normal))
    story.append(Paragraph(analysis, normal))
    story.append(Paragraph(f"<b>Recommendation</b>", normal))
    story.append(Paragraph(reco, normal))

    # ------------------ Page 3: SOC Threat Analytics Graph + analysis ------------------
    story.append(Paragraph("SOC Threat Analytics", h2))
    if soc_trend_fig is not None and (go is not None or px is not None):
        img_bio = _plotly_to_png_bytes(soc_trend_fig, width=900, height=350)
        if img_bio:
            story.append(RLImage(img_bio, width=content_width * 0.95, height=content_width * 0.95 * 0.4))
    else:
        # Try to build a simple trend from attack_timeline_df if available
        try:
            if pd is not None and attack_timeline_df is not None:
                df = attack_timeline_df if isinstance(attack_timeline_df, pd.DataFrame) else pd.DataFrame(attack_timeline_df)
                if "Time" in df.columns:
                    # create a simple count by Stage chart
                    cnt = df.groupby("Stage").size().reset_index(name="count")
                    if px is not None and not cnt.empty:
                        fig = px.bar(cnt, x="Stage", y="count", title="Events by Stage")
                        img_bio = _plotly_to_png_bytes(fig, width=700, height=350)
                        if img_bio:
                            story.append(RLImage(img_bio, width=content_width * 0.95, height=content_width * 0.95 * 0.4))
        except Exception:
            pass

    obs, analysis, reco = _make_chart_commentary(soc_metrics or {}, "soc_trend")
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>Observation</b>", normal))
    story.append(Paragraph(obs, normal))
    story.append(Paragraph(f"<b>SOC Analysis</b>", normal))
    story.append(Paragraph(analysis, normal))
    story.append(Paragraph(f"<b>Recommendation</b>", normal))
    story.append(Paragraph(reco, normal))

    # ------------------ Page 4: Attack Timeline ------------------
    # Ensure the Attack Timeline starts on a new page (Page 2 of content)
    # Insert Defender Activity Summary page before the Attack Timeline
    story.append(PageBreak())
    story.append(Paragraph("Defender Activity Summary", h2))
    # Compose defender activity table from soc_metrics
    def_actions = {
        "Isolation Actions": soc_metrics.get("isolation_actions", 0),
        "Recovery Actions": soc_metrics.get("recovery_actions", 0),
        "Block Actions": soc_metrics.get("block_actions", 0),
        "Priority Actions": soc_metrics.get("priority_actions", 0),
    }
    rewards = {
        "Attacker Reward": soc_metrics.get("attacker_reward", 0.0),
        "Defender Reward": soc_metrics.get("defender_reward", 0.0),
    }
    node_aggs = {
        "Nodes Recovered": soc_metrics.get("nodes_recovered", 0),
        "Nodes Isolated": soc_metrics.get("nodes_isolated", 0),
        "Nodes Blocked": soc_metrics.get("nodes_blocked", 0),
    }
    # FIX #1/#30: Winner based on actual simulation outcome, not just reward comparison.
    # Attacker wins if: exfiltration occurred, OR compromised count >= node threshold,
    # OR attack success rate high AND defense effectiveness low.
    # Defender wins only if they contained the attack with meaningful effectiveness.
    try:
        _compromised = soc_metrics.get("compromised_count", 0) or 0
        _node_count = soc_metrics.get("total_nodes", 6) or 6
        _exfil_flag = (str(soc_metrics.get("attack_stage", "") or "").lower() == "exfiltration")
        _atk_success_rate = float(soc_metrics.get("attack_success_rate", 0) or 0)
        _def_effectiveness = float(soc_metrics.get("defense_effectiveness", 0) or 0)
        _incident_status = str(soc_metrics.get("incident_status", "") or "").upper()
        # Attacker wins conditions
        _atk_wins = (
            _exfil_flag or
            _compromised >= (_node_count - 1) or
            (_atk_success_rate >= 70 and _def_effectiveness < 25) or
            "BREACH" in _incident_status
        )
        # If no decisive win, determine by relative performance
        if _atk_wins:
            final_winner = "Attacker"
        elif _def_effectiveness >= 50 and _compromised == 0:
            final_winner = "Defender"
        elif float(rewards["Defender Reward"]) > float(rewards["Attacker Reward"]) * 1.5:
            final_winner = "Defender"
        elif float(rewards["Attacker Reward"]) > float(rewards["Defender Reward"]) * 1.5:
            final_winner = "Attacker"
        else:
            final_winner = "Draw / Indeterminate"
    except Exception:
        final_winner = "Undetermined"

    # Build table rows
    das_rows = []
    for k, v in def_actions.items():
        das_rows.append([Paragraph(f"<b>{k}</b>", normal), Paragraph(str(v), normal)])
    for k, v in node_aggs.items():
        das_rows.append([Paragraph(f"<b>{k}</b>", normal), Paragraph(str(v), normal)])
    for k, v in rewards.items():
        das_rows.append([Paragraph(f"<b>{k}</b>", normal), Paragraph(str(v), normal)])
    das_rows.append([Paragraph("<b>Defense Effectiveness</b>", normal), Paragraph(str(soc_metrics.get("defense_effectiveness", "N/A"),), normal)])
    das_rows.append([Paragraph("<b>Final Winner</b>", normal), Paragraph(str(final_winner), normal)])

    das_table = Table(das_rows, colWidths=[2.5 * inch, content_width - 2.5 * inch])
    das_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BOX", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    story.append(das_table)
    story.append(Spacer(1, 8))

    # Start the Attack Timeline page after the Defender Activity Summary
    story.append(PageBreak())
    story.append(Paragraph("Attack Timeline", h2))
    # Keep only important columns and paginate
    timeline_cols = ["Time", "Stage", "Severity", "Technique", "Target Node", "CVE"]
    # Coerce to DataFrame-like list of dicts
    rows = []
    try:
        if attack_timeline_df is None:
            rows = []
        elif pd is not None and isinstance(attack_timeline_df, pd.DataFrame):
            rows = attack_timeline_df.to_dict(orient="records")
        elif isinstance(attack_timeline_df, list):
            rows = attack_timeline_df
    except Exception:
        rows = []

    if rows:
        # Build a single table and let ReportLab split it across pages naturally
        hdr = [Paragraph(c, small) for c in ["Time", "Stage", "Severity", "Technique", "Target", "CVE"]]
        data = [hdr]
        for r in rows:
            time = _clean_cell_text(r.get("Time") or r.get("time") or "")
            stage = _clean_cell_text(r.get("Stage") or r.get("stage") or "")
            sev = _clean_cell_text(r.get("Severity") or r.get("severity") or "")
            tech = _clean_cell_text(r.get("Technique") or r.get("technique") or "")
            target = _clean_cell_text(r.get("Target Node") or r.get("Target") or r.get("target") or r.get("TargetHost") or "")
            cve = _clean_cell_text(r.get("CVE") or "")
            data.append([
                _to_paragraph(time, style=small),
                _to_paragraph(stage, style=small),
                _to_paragraph(sev, style=small),
                _to_paragraph(tech, style=small),
                _to_paragraph(target, style=small),
                _to_paragraph(cve, style=small),
            ])
        # sensible column widths, scaled to available width
        col_widths = [1.2 * inch, 0.9 * inch, 0.8 * inch, 2.0 * inch, 1.3 * inch, 0.6 * inch]
        total = sum(col_widths)
        factor = content_width / total if total > 0 else 1.0
        col_widths = [w * factor for w in col_widths]
        tbl = Table(data, colWidths=col_widths, repeatRows=1)
        tbl_style = TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f7f9")]),
        ])
        tbl.setStyle(tbl_style)
        story.append(tbl)
    else:
        story.append(Paragraph("No timeline events available.", normal))

    # ------------------ Page 5: MITRE ATT&CK Analytics + pie ------------------
    # Force MITRE section to start on its own page so the timeline page remains dedicated.
    story.append(PageBreak())
    mitre_block = []
    # Escape ampersand for ReportLab Paragraph processing so it renders correctly
    mitre_block.append(Paragraph("MITRE ATT&amp;CK Analytics", h2))
    mitre_fig = None
    # Prefer the persisted dashboard Plotly figure when available
    try:
        import streamlit as st
        for key in ("mitre_pie_fig", "mitre_pie_chart", "mitre_fig", "mitre_chart"):
            v = st.session_state.get(key)
            if v is not None:
                mitre_fig = v
                break
    except Exception:
        mitre_fig = None

    # Fallback: attempt to reconstruct using analytics.build_mitre_pie or DataFrame
    if mitre_fig is None:
        try:
            try:
                from analytics import build_mitre_pie as _build_mitre_pie
            except Exception:
                _build_mitre_pie = None

            technique_counts = {}
            if pd is not None and isinstance(mitre_df, pd.DataFrame) and not mitre_df.empty:
                cols = list(mitre_df.columns)
                if len(cols) >= 2:
                    try:
                        technique_counts = dict(zip(mitre_df.iloc[:, 0].astype(str), mitre_df.iloc[:, 1].astype(int)))
                    except Exception:
                        technique_counts = dict(zip(mitre_df.iloc[:, 0].astype(str), mitre_df.iloc[:, 1].astype(str)))
            elif isinstance(mitre_df, dict):
                technique_counts = mitre_df
            elif isinstance(mitre_df, list) and mitre_df:
                if isinstance(mitre_df[0], dict):
                    keys = list(mitre_df[0].keys())
                    if len(keys) >= 2:
                        k0, k1 = keys[0], keys[1]
                        try:
                            technique_counts = {str(r.get(k0)): int(r.get(k1, 0)) for r in mitre_df}
                        except Exception:
                            technique_counts = {str(r.get(k0)): r.get(k1, 0) for r in mitre_df}

            if _build_mitre_pie is not None and technique_counts:
                try:
                    mitre_fig = _build_mitre_pie(technique_counts)
                except Exception:
                    mitre_fig = None
            elif pd is not None and isinstance(mitre_df, pd.DataFrame) and not mitre_df.empty and px is not None:
                try:
                    mitre_fig = px.pie(
                        mitre_df,
                        names=mitre_df.columns[0],
                        values=mitre_df.columns[1],
                        title="MITRE ATT&CK Technique Distribution",
                        color_discrete_sequence=px.colors.sequential.Blues_r,
                        hole=0.45,
                    )
                    mitre_fig.update_layout(
                        autosize=True,
                        paper_bgcolor="#071028",
                        plot_bgcolor="#071028",
                        font_color="white",
                        legend=dict(orientation="h", yanchor="top", y=-0.1, xanchor="center", x=0.5, font=dict(size=10)),
                        margin=dict(l=10, r=10, t=40, b=40),
                        height=350,
                    )
                except Exception:
                    mitre_fig = None
        except Exception:
            mitre_fig = None

    # Attempt to export the persisted dashboard figure first; if that fails,
    # reconstruct a small Pie from `mitre_df` (or analytics) and export that instead.
    if (go is not None or px is not None):
        exported = False
        # Try session-provided figure first
        if mitre_fig is not None:
            print("[pdf_exporter] Attempting to export persisted dashboard MITRE figure...")
            img_bio = _plotly_to_png_bytes(mitre_fig, width=1000, height=600)
            if img_bio:
                try:
                    mitre_chart = RLImage(img_bio, width=500, height=300)
                    try:
                        mitre_chart.hAlign = "CENTER"
                    except Exception:
                        pass
                    mitre_block.append(mitre_chart)
                    exported = True
                except Exception:
                    import traceback

                    print("Failed to convert exported MITRE image to ReportLab image.")
                    traceback.print_exc()
                    raise
            else:
                print("[pdf_exporter] Persisted MITRE figure export failed; will attempt to reconstruct from data.")

        # If not exported yet, try to reconstruct from mitre_df or analytics.build_mitre_pie
        if not exported:
            print("[pdf_exporter] Reconstructing MITRE pie from data...")
            recon_fig = None
            try:
                try:
                    from analytics import build_mitre_pie as _build_mitre_pie
                except Exception:
                    _build_mitre_pie = None

                technique_counts = {}
                if pd is not None and isinstance(mitre_df, pd.DataFrame) and not mitre_df.empty:
                    cols = list(mitre_df.columns)
                    if len(cols) >= 2:
                        try:
                            technique_counts = dict(zip(mitre_df.iloc[:, 0].astype(str), mitre_df.iloc[:, 1].astype(int)))
                        except Exception:
                            technique_counts = dict(zip(mitre_df.iloc[:, 0].astype(str), mitre_df.iloc[:, 1].astype(str)))
                elif isinstance(mitre_df, dict):
                    technique_counts = mitre_df
                elif isinstance(mitre_df, list) and mitre_df:
                    if isinstance(mitre_df[0], dict):
                        keys = list(mitre_df[0].keys())
                        if len(keys) >= 2:
                            k0, k1 = keys[0], keys[1]
                            try:
                                technique_counts = {str(r.get(k0)): int(r.get(k1, 0)) for r in mitre_df}
                            except Exception:
                                technique_counts = {str(r.get(k0)): r.get(k1, 0) for r in mitre_df}

                if _build_mitre_pie is not None and technique_counts:
                    try:
                        recon_fig = _build_mitre_pie(technique_counts)
                    except Exception:
                        recon_fig = None
                elif pd is not None and isinstance(mitre_df, pd.DataFrame) and not mitre_df.empty and px is not None:
                    try:
                        recon_fig = px.pie(
                            mitre_df,
                            names=mitre_df.columns[0],
                            values=mitre_df.columns[1],
                            title="MITRE ATT&CK Technique Distribution",
                            color_discrete_sequence=px.colors.sequential.Blues_r,
                            hole=0.45,
                        )
                        recon_fig.update_layout(
                            autosize=True,
                            paper_bgcolor="#071028",
                            plot_bgcolor="#071028",
                            font_color="white",
                            legend=dict(orientation="h", yanchor="top", y=-0.1, xanchor="center", x=0.5, font=dict(size=10)),
                            margin=dict(l=10, r=10, t=40, b=40),
                            height=350,
                        )
                    except Exception:
                        recon_fig = None
            except Exception:
                recon_fig = None

            if recon_fig is not None:
                print("[pdf_exporter] Exporting reconstructed MITRE pie...")
                img_bio2 = _plotly_to_png_bytes(recon_fig, width=1000, height=600)
                if img_bio2:
                    try:
                        mitre_chart = RLImage(img_bio2, width=500, height=300)
                        try:
                            mitre_chart.hAlign = "CENTER"
                        except Exception:
                            pass
                        mitre_block.append(mitre_chart)
                        exported = True
                    except Exception:
                        import traceback

                        print("Failed to convert reconstructed MITRE image to ReportLab image.")
                        traceback.print_exc()
                        raise
                else:
                    print("[pdf_exporter] Reconstructed MITRE export failed (kaleido+fallback).")

        if not exported:
            import sys, traceback

            print("MITRE pie export failed: attempted persisted fig and reconstructed fig; see prior tracebacks for details.")
            traceback.print_exc()
            raise RuntimeError(
                "Plotly image export failed. Ensure Kaleido is installed into the Python environment used by Streamlit:\n\n"
                f"    {sys.executable} -m pip install --upgrade kaleido\n\n"
                "Then restart the Streamlit server and retry."
            )
    # If no figure was available, do not render placeholder text — continue to narrative

    # Short executive narrative blocks (templated per request)
    mitre_block.append(Spacer(1, 8))
    mitre_block.append(Paragraph("<b>Observation</b>", normal))
    mitre_block.append(Paragraph("Persistence and exfiltration techniques dominated the attack lifecycle.", normal))
    mitre_block.append(Paragraph("<b>SOC Analysis</b>", normal))
    mitre_block.append(Paragraph("Observed techniques indicate multi-stage attack activity. Review IOC registry for correlated CVEs and impacted assets.", normal))
    mitre_block.append(Paragraph("<b>Recommendation</b>", normal))
    mitre_block.append(Paragraph("Prioritize containment and credential isolation to reduce lateral movement.", normal))

    # Keep the MITRE title, chart, and narrative together when possible
    try:
        story.append(KeepTogether(mitre_block))
    except Exception:
        # Fallback: append items individually if KeepTogether fails
        for it in mitre_block:
            story.append(it)

    # ------------------ Page 6: IOC Registry + Executive Recommendations (last page) ------------------
    # Force IOC and Executive Recommendations to appear together on the final page
    story.append(PageBreak())
    page4_block = []
    page4_block.append(Paragraph("IOC Intelligence Registry", h2))
    if _has_data(ioc_df):
        try:
            ioc_rows = ioc_df.to_dict(orient="records") if pd is not None and isinstance(ioc_df, pd.DataFrame) else ioc_df
            # FIX: Add Asset and CVSS columns to IOC table in PDF
            headers = ["IOC", "Type", "Severity", "Asset", "CVSS", "Count", "Confidence"]
            data = [[Paragraph(h, small) for h in headers]]
            for r in ioc_rows:
                # For CVE rows, show CVSS from enrichment; for others leave blank
                cvss_val = str(r.get("CVSS") or "") if r.get("Type") in ("CVE", "Adversary Technique") else ""
                asset_val = str(r.get("Asset") or "")
                row = [
                    _to_paragraph(r.get("IOC") or r.get("ioc"), style=small),
                    _to_paragraph(r.get("Type") or r.get("type"), style=small),
                    _to_paragraph(r.get("Severity") or r.get("severity"), style=small),
                    _to_paragraph(asset_val, style=small),
                    _to_paragraph(cvss_val, style=small),
                    _to_paragraph(r.get("Count") or r.get("count"), style=small),
                    _to_paragraph(r.get("Confidence") or r.get("confidence"), style=small),
                ]
                data.append(row)
            colw = [1.6 * inch, 0.85 * inch, 0.75 * inch, 0.9 * inch, 0.55 * inch, 0.5 * inch, 0.75 * inch]
            tbl = Table(data, colWidths=colw)
            ts = TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
            # severity coloring for rows
            for i, r in enumerate(ioc_rows, start=1):
                sev = (r.get("Severity") or r.get("severity") or "").lower()
                bg = colors.white
                if "critical" in sev:
                    bg = colors.HexColor("#fde8e8")
                elif "high" in sev:
                    bg = colors.HexColor("#fff4e6")
                elif "medium" in sev:
                    bg = colors.HexColor("#fff7ed")
                elif "low" in sev:
                    bg = colors.HexColor("#fffbea")
                ts.add("BACKGROUND", (0, i), (-1, i), bg)
            tbl.setStyle(ts)
            page4_block.append(tbl)
        except Exception:
            page4_block.append(Paragraph("IOC data could not be rendered.", normal))
    else:
        page4_block.append(Paragraph("No IOC indicators available.", normal))

    # FIX: Add "CVEs Exploited" summary section after IOC table
    page4_block.append(Spacer(1, 10))
    page4_block.append(Paragraph("CVEs Exploited During Campaign", h2))
    try:
        if _has_data(ioc_df):
            _ioc_rows_cve = ioc_df.to_dict(orient="records") if pd is not None and isinstance(ioc_df, pd.DataFrame) else []
            _cve_rows = [r for r in _ioc_rows_cve if str(r.get("Type", "")).strip() == "CVE"]
            if _cve_rows:
                cve_summary_data = [[
                    Paragraph("<b>CVE ID</b>", small),
                    Paragraph("<b>Asset</b>", small),
                    Paragraph("<b>CVSS</b>", small),
                    Paragraph("<b>MITRE</b>", small),
                    Paragraph("<b>Severity</b>", small),
                    Paragraph("<b>Confidence</b>", small),
                ]]
                for _cr in _cve_rows:
                    cve_summary_data.append([
                        _to_paragraph(_cr.get("IOC") or "", style=small),
                        _to_paragraph(_cr.get("Asset") or "", style=small),
                        _to_paragraph(str(_cr.get("CVSS") or ""), style=small),
                        _to_paragraph(_cr.get("MITRE") or "", style=small),
                        _to_paragraph(_cr.get("Severity") or "", style=small),
                        _to_paragraph(str(_cr.get("Confidence") or ""), style=small),
                    ])
                _cve_colw = [1.8*inch, 1.0*inch, 0.6*inch, 0.8*inch, 0.8*inch, 0.85*inch]
                _cve_tbl = Table(cve_summary_data, colWidths=_cve_colw)
                _cve_ts = TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
                for _i, _cr in enumerate(_cve_rows, start=1):
                    _sev = str(_cr.get("Severity") or "").lower()
                    _bg = colors.white
                    if "critical" in _sev:
                        _bg = colors.HexColor("#fde8e8")
                    elif "high" in _sev:
                        _bg = colors.HexColor("#fff4e6")
                    _cve_ts.add("BACKGROUND", (0, _i), (-1, _i), _bg)
                _cve_tbl.setStyle(_cve_ts)
                page4_block.append(_cve_tbl)
            else:
                page4_block.append(Paragraph("No CVEs were observed during this simulation.", normal))
    except Exception:
        page4_block.append(Paragraph("CVE data could not be rendered.", normal))

    # Executive Recommendations follow immediately after the CVE table
    tactical = (soc_metrics or {}).get("tactical_recommendation") or []
    exec_strategy = (soc_metrics or {}).get("executive_response_strategy") or ""
    page4_block.append(Spacer(1, 8))
    page4_block.append(Paragraph("Executive Recommendations", h2))
    if tactical:
        page4_block.append(Paragraph("<b>Tactical Recommendations</b>", normal))
        page4_block.append(_to_paragraph(tactical, style=normal))
    else:
        page4_block.append(Paragraph("No tactical recommendations available.", normal))
    page4_block.append(Spacer(1, 8))
    page4_block.append(Paragraph("<b>Executive Response Strategy</b>", normal))
    if exec_strategy:
        page4_block.append(_to_paragraph(exec_strategy, style=normal))
    else:
        page4_block.append(Paragraph("No executive strategy available.", normal))

    # Keep the IOC and Executive Recommendations together when possible
    try:
        story.append(KeepTogether(page4_block))
    except Exception:
        for it in page4_block:
            story.append(it)

    # Build PDF with header/footer
    try:
        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
        pdf_bytes = buffer.getvalue()
    finally:
        buffer.close()

    return pdf_bytes