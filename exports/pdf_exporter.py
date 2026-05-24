"""
exports/pdf_exporter.py
-----------------------
Responsible for generating an in-memory Executive SOC Incident Report PDF
using ReportLab. Produces a bytes object suitable for Streamlit's
`st.download_button` without writing any temporary files.
"""
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
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
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=22,
        alignment=1,
        spaceAfter=12,
    )
    heading = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=12, leading=14)
    normal = styles["Normal"]
    normal.spaceAfter = 6

    story = []

    # Page 1 — Executive Summary
    story.append(Paragraph("CYBER MARL SOC PLATFORM — INCIDENT REPORT", title_style))
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    story.append(Paragraph(f"Generated: {ts}", normal))

    incident_status = soc_metrics.get("incident_status") if soc_metrics else sidebar_summary.get("status", "N/A")
    threat_level = soc_metrics.get("threat_level") if soc_metrics else sidebar_summary.get("threat", "N/A")
    risk_score = soc_metrics.get("risk_score") if soc_metrics else sidebar_summary.get("risk", 0.0)
    compromised_assets = soc_metrics.get("compromised_assets") if soc_metrics else []
    defense_eff = soc_metrics.get("defense_effectiveness") if soc_metrics else "N/A"
    soc_reco = soc_metrics.get("soc_recommendation") if soc_metrics else "N/A"

    summary_table = [
        ["Incident Status:", str(incident_status)],
        ["Threat Level:", str(threat_level)],
        ["Risk Score:", str(risk_score)],
        ["Compromised Assets:", ", ".join(sorted(list(compromised_assets))[:10]) if compromised_assets else "None"],
        ["Defense Effectiveness:", str(defense_eff)],
        ["SOC Recommendation:", str(soc_reco)],
    ]
    story.append(Spacer(1, 6))
    story.append(_styled_table([[c for c, _ in summary_table]] + [["", ""]], font_size=10) or Spacer(1, 6))
    # Instead of rendering the table above, use paragraphs for readability
    for k, v in summary_table:
        story.append(Paragraph(f"<b>{k}</b> {v}", normal))

    story.append(PageBreak())

    # Page 2 — Attack Timeline (most recent rows)
    story.append(Paragraph("Attack Timeline (most recent events)", heading))
    if attack_timeline_df is not None:
        cols = [
            c for c in ["Time", "Stage", "Severity", "Technique", "Target Node", "CVE", "Event Summary"]
            if (pd is None or c in getattr(attack_timeline_df, "columns", [])) or (isinstance(attack_timeline_df, list) and attack_timeline_df and c in attack_timeline_df[0].keys())
        ]
        data = _df_to_table_data(attack_timeline_df, max_rows=30, columns=cols)
        tbl = _styled_table(data, font_size=8)
        if tbl:
            story.append(tbl)
        else:
            story.append(Paragraph("No timeline events available.", normal))
    else:
        story.append(Paragraph("No timeline events available.", normal))

    story.append(PageBreak())

    # Page 3 — MITRE ATT&CK Analytics
    story.append(Paragraph("MITRE ATT&CK Analytics", heading))
    if mitre_df is not None:
        data = _df_to_table_data(mitre_df, max_rows=40)
        tbl = _styled_table(data, font_size=9)
        if tbl:
            story.append(tbl)
        else:
            story.append(Paragraph("No MITRE technique data available.", normal))
    else:
        story.append(Paragraph("No MITRE technique data available.", normal))

    story.append(PageBreak())

    # Page 4 — IOC Intelligence
    story.append(Paragraph("IOC Intelligence Registry", heading))
    if ioc_df is not None:
        # prefer common columns if present
        preferred_cols = ["IOC", "Type", "Severity", "First Seen", "Count", "Confidence"]
        data = _df_to_table_data(ioc_df, max_rows=60, columns=preferred_cols)
        tbl = _styled_table(data, font_size=9)
        if tbl:
            story.append(tbl)
        else:
            story.append(Paragraph("No IOC indicators available.", normal))
    else:
        story.append(Paragraph("No IOC indicators available.", normal))

    story.append(PageBreak())

    # Page 5 — Live Threat Feed
    story.append(Paragraph("Live Threat Feed", heading))
    if live_feed:
        for line in (live_feed[:40] if isinstance(live_feed, list) else []):
            story.append(Paragraph(str(line), normal))
    else:
        story.append(Paragraph("No live feed entries available.", normal))

    story.append(PageBreak())

    # Page 6 — Executive Recommendations
    story.append(Paragraph("Executive Recommendations", heading))
    # Tactical recommendations
    tactical = soc_metrics.get("tactical_recommendation") if soc_metrics else None
    exec_strategy = soc_metrics.get("executive_response_strategy") if soc_metrics else None

    story.append(Paragraph("<b>Tactical Recommendations:</b>", normal))
    if tactical:
        for r in tactical:
            story.append(Paragraph(f"- {r}", normal))
    else:
        story.append(Paragraph("No tactical recommendations available.", normal))

    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>Executive Response Strategy:</b>", normal))
    if exec_strategy:
        story.append(Paragraph(exec_strategy, normal))
    else:
        story.append(Paragraph("No executive strategy available.", normal))

    # Build PDF
    try:
        doc.build(story)
        pdf_bytes = buffer.getvalue()
    finally:
        buffer.close()

    return pdf_bytes
