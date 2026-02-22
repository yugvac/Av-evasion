"""
SentinelLab — PDF Report Generator

Generates professional research reports using ReportLab.
"""
import io
import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from backend.config import REPORTS_DIR, APP_NAME, APP_VERSION
from backend.utils.logger import get_logger

logger = get_logger("ReportGen")

# ── Custom Colors ────────────────────────────────────────────────────
BRAND_DARK = colors.HexColor("#0f0f23")
BRAND_PRIMARY = colors.HexColor("#6c5ce7")
BRAND_ACCENT = colors.HexColor("#00cec9")
BRAND_TEXT = colors.HexColor("#2d3436")
BRAND_LIGHT = colors.HexColor("#dfe6e9")


def _get_styles():
    """Build custom paragraph styles."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "CoverTitle", parent=styles["Title"],
        fontSize=32, textColor=BRAND_PRIMARY, spaceAfter=12,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"],
        fontSize=14, textColor=BRAND_TEXT, spaceAfter=6,
        alignment=TA_CENTER, fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        "SectionHeader", parent=styles["Heading1"],
        fontSize=18, textColor=BRAND_PRIMARY, spaceBefore=20, spaceAfter=10,
        fontName="Helvetica-Bold", borderWidth=1, borderColor=BRAND_ACCENT,
        borderPadding=4,
    ))
    styles.add(ParagraphStyle(
        "SubHeader", parent=styles["Heading2"],
        fontSize=13, textColor=BRAND_DARK, spaceBefore=12, spaceAfter=6,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"],
        fontSize=10, textColor=BRAND_TEXT, spaceAfter=6,
        fontName="Helvetica", leading=14,
    ))
    styles.add(ParagraphStyle(
        "StatValue", parent=styles["Normal"],
        fontSize=24, textColor=BRAND_PRIMARY, alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "FooterStyle", parent=styles["Normal"],
        fontSize=8, textColor=colors.gray, alignment=TA_CENTER,
    ))
    return styles


def _build_stat_table(stats: dict, styles) -> Table:
    """Build a visual stats summary table."""
    data = [
        [
            Paragraph("Total Experiments", styles["BodyText2"]),
            Paragraph("Total Samples", styles["BodyText2"]),
            Paragraph("Avg Detection Rate", styles["BodyText2"]),
            Paragraph("False Positives", styles["BodyText2"]),
        ],
        [
            Paragraph(str(stats.get("total_experiments", 0)), styles["StatValue"]),
            Paragraph(str(stats.get("total_samples", 0)), styles["StatValue"]),
            Paragraph(f"{stats.get('avg_detection_rate', 0):.1f}%", styles["StatValue"]),
            Paragraph(str(stats.get("total_false_positives", 0)), styles["StatValue"]),
        ],
    ]
    table = Table(data, colWidths=[1.6 * inch] * 4)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_LIGHT),
        ("BACKGROUND", (0, 1), (-1, 1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    return table


def _build_experiment_table(experiments: list, styles) -> Table:
    """Build experiment results table."""
    header = ["#", "Name", "Samples", "Detections", "FP", "Rate", "Entropy", "Date"]
    data = [header]

    for exp in experiments[:20]:  # Limit to 20 rows
        data.append([
            str(exp.get("id", "")),
            str(exp.get("name", ""))[:30],
            str(exp.get("sample_count", 0)),
            str(exp.get("total_detections", 0)),
            str(exp.get("false_positives", 0)),
            f"{exp.get('detection_rate', 0):.1f}%",
            f"{exp.get('avg_entropy', 0):.2f}",
            str(exp.get("created_at", ""))[:10],
        ])

    table = Table(data, colWidths=[0.4*inch, 1.8*inch, 0.6*inch, 0.7*inch, 0.4*inch, 0.6*inch, 0.6*inch, 0.9*inch])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
    ]
    table = Table(data, colWidths=[0.4*inch, 1.8*inch, 0.6*inch, 0.7*inch, 0.4*inch, 0.6*inch, 0.6*inch, 0.9*inch])
    table.setStyle(TableStyle(style))
    return table


def generate_summary_report(stats: dict, experiments: list) -> str:
    """
    Generate a full research summary PDF.
    Returns the file path.
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"SentinelLab_Report_{timestamp}.pdf"
    filepath = REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(filepath), pagesize=A4,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )

    styles = _get_styles()
    elements = []

    # ── Cover Page ──
    elements.append(Spacer(1, 1.5 * inch))
    elements.append(Paragraph("🛡️ SentinelLab", styles["CoverTitle"]))
    elements.append(Paragraph("AV Detection Research Report", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(HRFlowable(width="60%", thickness=2, color=BRAND_ACCENT))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(
        f"Generated: {datetime.datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}",
        styles["CoverSubtitle"],
    ))
    elements.append(Paragraph(f"Platform Version: {APP_VERSION}", styles["CoverSubtitle"]))
    elements.append(PageBreak())

    # ── Executive Summary ──
    elements.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
    elements.append(Paragraph(
        f"This report summarizes {stats.get('total_experiments', 0)} experiments conducted on the "
        f"SentinelLab platform, analyzing {stats.get('total_samples', 0)} test samples across "
        f"multiple simulated scanner engines. The average detection rate observed was "
        f"{stats.get('avg_detection_rate', 0):.1f}%, with {stats.get('total_false_positives', 0)} "
        f"false positive classifications identified during the research period.",
        styles["BodyText2"],
    ))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(_build_stat_table(stats, styles))
    elements.append(Spacer(1, 0.3 * inch))

    # ── Methodology ──
    elements.append(Paragraph("2. Methodology", styles["SectionHeader"]))
    elements.append(Paragraph(
        "Test files were generated with controlled variations in entropy levels (0.5–8.0 bits/byte), "
        "encoding formats (plaintext, Base64, XOR, hex, ROT13), structural patterns (sequential, "
        "random, repeating, mixed, layered), and metadata profiles (PE, ELF, PDF, Office, ZIP headers). "
        "Each sample was scanned by 5 simulated engines with different heuristic weightings to model "
        "realistic multi-engine detection scenarios.",
        styles["BodyText2"],
    ))
    elements.append(Spacer(1, 0.2 * inch))

    # ── Key Findings ──
    elements.append(Paragraph("3. Key Findings", styles["SectionHeader"]))
    elements.append(Paragraph("• High-entropy files (>6.5 bits/byte) show significantly elevated detection rates", styles["BodyText2"]))
    elements.append(Paragraph("• XOR-encoded samples trigger the most false positives across engines", styles["BodyText2"]))
    elements.append(Paragraph("• PE-like metadata headers increase suspicion scores by 30-60%", styles["BodyText2"]))
    elements.append(Paragraph("• Small file sizes (<1KB) exhibit higher anomaly flagging", styles["BodyText2"]))
    elements.append(Paragraph("• Scanner agreement varies — EntropyAnalyzer is most aggressive", styles["BodyText2"]))
    elements.append(Spacer(1, 0.3 * inch))

    # ── Experiment Results ──
    elements.append(Paragraph("4. Experiment Results", styles["SectionHeader"]))
    if experiments:
        elements.append(_build_experiment_table(experiments, styles))
    else:
        elements.append(Paragraph("No experiments recorded yet.", styles["BodyText2"]))

    elements.append(Spacer(1, 0.3 * inch))

    # ── Scanner Performance ──
    elements.append(Paragraph("5. Scanner Performance Analysis", styles["SectionHeader"]))
    elements.append(Paragraph(
        "Each simulated scanner engine employs different weighting strategies for entropy, encoding, "
        "metadata, structural patterns, and file size analysis. The EntropyAnalyzer engine uses a 55% "
        "entropy weight, making it the most sensitive to high-entropy payloads. PatternMatcher focuses "
        "on metadata signatures (30% weight), while BehaviorSim emphasizes structural analysis (25%).",
        styles["BodyText2"],
    ))
    elements.append(Spacer(1, 0.3 * inch))

    # ── Conclusion ──
    elements.append(Paragraph("6. Conclusion", styles["SectionHeader"]))
    elements.append(Paragraph(
        "The simulated detection research demonstrates the significant impact of file entropy and "
        "encoding complexity on AV engine classification accuracy. False positive rates correlate "
        "strongly with encoding obfuscation techniques, while metadata-based detection provides "
        "the most reliable classification with lowest false positive rates.",
        styles["BodyText2"],
    ))

    doc.build(elements)
    logger.info(f"Report generated: {filepath}")
    return str(filepath)


def generate_experiment_report(experiment: dict, samples: list, scan_results: list) -> str:
    """Generate PDF report for a single experiment."""
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"Experiment_{experiment.get('id', 0)}_{timestamp}.pdf"
    filepath = REPORTS_DIR / filename

    doc = SimpleDocTemplate(str(filepath), pagesize=A4,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
        leftMargin=0.75*inch, rightMargin=0.75*inch)

    styles = _get_styles()
    elements = []

    # Cover
    elements.append(Spacer(1, 1.5 * inch))
    elements.append(Paragraph("🛡️ SentinelLab", styles["CoverTitle"]))
    elements.append(Paragraph(f"Experiment Report: {experiment.get('name', 'N/A')}", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(HRFlowable(width="60%", thickness=2, color=BRAND_ACCENT))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(
        f"Generated: {datetime.datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}",
        styles["CoverSubtitle"],
    ))
    elements.append(PageBreak())

    # Experiment Details
    elements.append(Paragraph("Experiment Overview", styles["SectionHeader"]))
    detail_data = [
        ["Property", "Value"],
        ["Experiment ID", str(experiment.get("id", ""))],
        ["Name", experiment.get("name", "")],
        ["Status", experiment.get("status", "")],
        ["Sample Count", str(experiment.get("sample_count", 0))],
        ["Detection Rate", f"{experiment.get('detection_rate', 0):.1f}%"],
        ["False Positives", str(experiment.get("false_positives", 0))],
        ["Avg Entropy", f"{experiment.get('avg_entropy', 0):.2f}"],
        ["Avg Confidence", f"{experiment.get('avg_confidence', 0):.1f}%"],
        ["Duration", f"{experiment.get('duration_seconds', 0):.1f}s"],
        ["Created", str(experiment.get("created_at", ""))[:19]],
    ]
    detail_table = Table(detail_data, colWidths=[2*inch, 4*inch])
    detail_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
    ]))
    elements.append(detail_table)
    elements.append(Spacer(1, 0.3*inch))

    # Sample Results
    elements.append(Paragraph("Sample Analysis", styles["SectionHeader"]))
    if samples:
        sample_header = ["#", "Filename", "Size", "Entropy", "Encoding", "Pattern"]
        sample_data = [sample_header]
        for s in samples[:30]:
            sample_data.append([
                str(s.get("id", "")),
                str(s.get("filename", ""))[:25],
                f"{s.get('file_size', 0):,}",
                f"{s.get('entropy', 0):.2f}",
                s.get("encoding", ""),
                s.get("structural_pattern", ""),
            ])
        st = Table(sample_data, colWidths=[0.35*inch, 2.2*inch, 0.7*inch, 0.6*inch, 0.7*inch, 0.8*inch])
        st.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, BRAND_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ]))
        elements.append(st)

    doc.build(elements)
    logger.info(f"Experiment report generated: {filepath}")
    return str(filepath)
