"""Human-readable static analysis reports."""

from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, Iterator, Tuple

from .visualizer import ranked_strings


def _label(key: str) -> str:
    return key.replace("_", " ").capitalize()


def _entries(value: Any, depth: int = 0) -> Iterator[Tuple[int, str]]:
    if isinstance(value, dict):
        if not value:
            yield depth, "None"
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                yield depth, _label(key)
                yield from _entries(item, depth + 1)
            else:
                yield depth, f"{_label(key)}: {item if item is not None else 'Unavailable'}"
    elif isinstance(value, list):
        if not value:
            yield depth, "None"
        for index, item in enumerate(value):
            if isinstance(item, (dict, list)):
                yield depth, f"Entry {index}"
                yield from _entries(item, depth + 1)
            else:
                yield depth, str(item)
    else:
        yield depth, str(value) if value is not None else "Unavailable"


def report_sections(report: Dict[str, Any]) -> Iterator[Tuple[str, list]]:
    pe = report["pe_metadata"]
    packing = pe["packing"]
    prediction = packing["model"].get("prediction")
    summary = [
        (0, f"Status: {report['status']}"),
        (0, f"Scope: {'Packing assessment only' if report.get('mode') == 'packing' else 'Full collection'}"),
        (0, f"File: {pe['file_path']}"),
        (0, f"SHA-256: {pe['hashes']['sha256']}"),
        (0, f"Packing assessment: {'Likely packed' if packing['is_packed'] else 'No packing indicators detected'}"
         if pe["is_valid_pe"] else "Packing assessment: Invalid PE"),
        (0, f"Model prediction: {prediction['label']}" if prediction else "Model prediction: Unavailable"),
        (0, "Indicators and model predictions are investigative leads, not proof of maliciousness or behavior."),
    ]
    yield "Executive summary", summary
    labels = {
        "pe_metadata": "File metadata and packing assessment",
        "unpacking": "Unpacking",
        "analyzed_file": "Analyzed file",
        "packed_file_apis": "Packed original API tables",
        "apis": "Collected API tables",
        "categorized_strings": "Categorized string candidates",
        "strings": "Extracted strings by model score",
        "ai_analysis": "Offline API analysis",
        "errors": "Collection errors",
    }
    for key, title in labels.items():
        if key not in report:
            continue
        if key == "strings" and report[key] is not None:
            entries = []
            for index, item in ranked_strings(report[key]):
                details = "; ".join(
                    f"{_label(field)}: {value if value is not None else 'Unavailable'}"
                    for field, value in item.items() if field != "value"
                )
                entries.append((0, f"Original string index {index} | {details}"))
                entries.append((1, f"Value: {item['value']}"))
        else:
            entries = list(_entries(report[key]))
        yield title, entries


def write_text_report(report: Dict[str, Any], file) -> None:
    file.write("AISA | STATIC ANALYSIS REPORT\n")
    for title, entries in report_sections(report):
        file.write(f"\n{title.upper()}\n{'-' * len(title)}\n")
        for depth, text in entries:
            file.write(f"{'  ' * depth}{text}\n")


def write_pdf_report(report: Dict[str, Any], file) -> None:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#183153"),
        fontSize=20, leading=24, spaceAfter=8,
    )
    section_style = ParagraphStyle(
        "ReportSection", parent=styles["Heading2"], textColor=colors.HexColor("#183153"),
        spaceBefore=12, spaceAfter=6, keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "ReportBody", parent=styles["BodyText"], fontSize=8.5, leading=12,
        spaceAfter=2, splitLongWords=True,
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story = [
        Paragraph("STATIC ANALYSIS REPORT", title_style),
        Paragraph(f"AISA | Generated {timestamp}", body_style),
        Spacer(1, 5 * mm),
    ]
    for title, entries in report_sections(report):
        story.append(Paragraph(escape(title), section_style))
        for depth, text in entries:
            style = ParagraphStyle(
                f"ReportBody{depth}", parent=body_style, leftIndent=min(depth, 5) * 10,
            )
            safe_text = escape(text).replace("\n", "<br/>").replace("\t", "    ")
            story.append(Paragraph(safe_text or " ", style))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(document.leftMargin, 12 * mm, "AISA | Static analysis")
        canvas.drawRightString(document.pagesize[0] - document.rightMargin, 12 * mm,
                               f"Page {document.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(file, title="AISA Static Analysis Report",
                                 leftMargin=18 * mm, rightMargin=18 * mm,
                                 topMargin=16 * mm, bottomMargin=20 * mm)
    document.build(story, onFirstPage=footer, onLaterPages=footer)
