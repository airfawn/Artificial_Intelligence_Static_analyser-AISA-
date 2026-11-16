"""Human-readable static analysis reports."""

from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, Iterator, Tuple

from .visualizer import ranked_strings


PDF_FINDING_LIMIT = 20
PDF_CATEGORY_LIMIT = 8
PDF_EVIDENCE_LIMIT = 4
PDF_TEXT_LIMIT = 240


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


def _pdf_text(value: Any) -> str:
    text = " ".join(str(value).split())
    if len(text) > PDF_TEXT_LIMIT:
        return f"{text[:PDF_TEXT_LIMIT]}... [truncated; see full report]"
    return text


def _pdf_limited(entries, limit: int, description: str):
    shown = entries[:limit]
    omitted = len(entries) - len(shown)
    if omitted:
        return shown, f"{omitted} additional {description} omitted; see the full JSON or text report."
    return shown, None


def pdf_report_sections(report: Dict[str, Any]) -> Iterator[Tuple[str, list]]:
    pe = report["pe_metadata"]
    packing = pe["packing"]
    prediction = packing["model"].get("prediction")
    summary = [
        (0, f"Status: {report['status']}"),
        (0, f"Scope: {'Packing assessment only' if report.get('mode') == 'packing' else 'Full collection'}"),
        (0, f"File: {_pdf_text(pe['file_path'])}"),
        (0, f"SHA-256: {pe['hashes']['sha256']}"),
        (0, f"Architecture: {pe['architecture']}; size: {pe['file_size']:,} bytes"),
        (0, "This is a limited findings summary. Use --format json or --format text for the full collection."),
        (0, "Indicators and model predictions are investigative leads, not proof of maliciousness or behavior."),
    ]
    analyzed = report.get("analyzed_file")
    if analyzed and analyzed["source"] == "unpacked":
        summary.append((0, f"Unpacked file SHA-256: {analyzed['hashes']['sha256']}"))
    yield "Executive summary", summary

    packer = packing["packer"]
    identity = packer["name"] or (
        "Ambiguous: " + ", ".join(item["name"] for item in packer["matches"])
        if packer["matches"] else "Unknown"
    )
    assessment = "Invalid PE" if not pe["is_valid_pe"] else (
        "Likely packed" if packing["is_packed"] else "No packing indicators detected"
    )
    packing_entries = [
        (0, f"Assessment: {assessment}; confidence: {packing['confidence']}"),
        (0, f"Section-name identification: {_pdf_text(identity)}"),
        (0, f"Model prediction: {_pdf_text(prediction['label'])}" if prediction
         else f"Model prediction: unavailable ({_pdf_text(packing['model']['message'])})"),
        (0, f"Experimental weighted score: {packing['weighted_score']['score']}"
         if packing["weighted_score"]["score"] is not None else "Experimental weighted score: unavailable"),
    ]
    if prediction:
        packing_entries.append((1, _pdf_text(packing["model"]["message"])))
    reasons, omission = _pdf_limited(packing["reasons"], PDF_CATEGORY_LIMIT, "packing reasons")
    packing_entries.extend((1, _pdf_text(reason)) for reason in reasons)
    if omission:
        packing_entries.append((1, omission))
    if "unpacking" in report:
        unpacking = report["unpacking"]
        packing_entries.append((0, f"Unpacking: {unpacking['status']} - {_pdf_text(unpacking['message'])}"))
    yield "Packing assessment", packing_entries

    errors = report.get("errors", [])
    if errors:
        shown, omission = _pdf_limited(errors, PDF_CATEGORY_LIMIT, "collection errors")
        entries = [(0, _pdf_text(error)) for error in shown]
        if omission:
            entries.append((0, omission))
        yield "Collection errors", entries

    if report.get("mode") == "packing":
        return

    analysis = report.get("ai_analysis")
    if not analysis:
        yield "Flagged API analysis", [
            (0, "Not performed. Run full collection without --collect-only, or use "
             "--collect-only=false, to include experimental offline API analysis.")
        ]
    elif analysis["status"] != "experimental":
        yield "Flagged API analysis", [
            (0, f"Status: {analysis['status']} - {_pdf_text(analysis.get('error') or analysis.get('message'))}")
        ]
    else:
        api_entries = [(0, _pdf_text(analysis["summary"]))]
        for key, label in (
            ("flagged_imports", "Flagged imports"),
            ("patterns", "API combinations"),
            ("observed_associations", "Corpus associations"),
        ):
            findings = analysis[key]
            api_entries.append((0, f"{label}: {len(findings)}"))
            shown, omission = _pdf_limited(findings, PDF_FINDING_LIMIT, label.lower())
            for item in shown:
                name = item.get("name") or item.get("id") or ", ".join(item.get("names", []))
                api_entries.append((1, f"{_pdf_text(name)}: {_pdf_text(item['suggestion'])}"))
                api_entries.append((2, f"Corpus: malware {item['malware_reports']}/{item['malware_total']}; "
                                    f"benign {item['benign_reports']}/{item['benign_total']}"))
                refs, refs_omitted = _pdf_limited(item["evidence"], PDF_EVIDENCE_LIMIT, "API references")
                for ref in refs:
                    api_entries.append((2, f"Evidence: {ref['table']}[{ref['index']}] "
                                        f"{_pdf_text(ref.get('dll') or '?')}!{_pdf_text(ref['name'])}"))
                if refs_omitted:
                    api_entries.append((2, refs_omitted))
                families, family_omitted = _pdf_limited(
                    item.get("weak_family_counts", []), PDF_EVIDENCE_LIMIT, "unverified family associations"
                )
                for family in families:
                    api_entries.append((2, f"Unverified family {_pdf_text(family['label'])}: "
                                        f"{family['count']}/{family['samples']}"))
                if family_omitted:
                    api_entries.append((2, family_omitted))
            if omission:
                api_entries.append((1, omission))
        api_entries.extend((0, _pdf_text(limitation)) for limitation in analysis["limitations"])
        yield "Flagged API analysis", api_entries

    strings = report.get("strings")
    categories = report.get("categorized_strings")
    if strings is None or categories is None:
        yield "String evidence", [(0, "Strings and categorized indicators were not collected.")]
        return

    category_entries = [
        (0, "Pattern-matched candidates, not verified behavior. Results are ordered by source string score."),
        (0, "Values are previews with whitespace normalized; use the full report for exact evidence."),
    ]
    for key, label in (("domains", "Domains"), ("urls", "URLs"),
                       ("file_paths", "File paths"), ("commands", "Commands")):
        candidates = categories[key]
        ranked = sorted(candidates, key=lambda item: (
            strings[item["string_index"]].get("model_score") is None,
            -(strings[item["string_index"]].get("model_score") or 0),
        ))
        category_entries.append((0, f"{label}: {len(candidates)}"))
        shown, omission = _pdf_limited(ranked, PDF_CATEGORY_LIMIT, f"{label.lower()} candidates")
        for item in shown:
            category_entries.append((1, f"String [{item['string_index']}] at {hex(item['string_offset'])}: "
                                     f"{_pdf_text(item['value'])}"))
        if omission:
            category_entries.append((1, omission))
    yield "Categorized indicator candidates", category_entries

    flagged = [(index, entry) for index, entry in ranked_strings(strings) if entry.get("model_suspicious")]
    string_entries = [
        (0, f"Model-flagged strings: {len(flagged)} of {len(strings)} extracted; scores are not file verdicts."),
        (0, "Values are previews with whitespace normalized; use the full report for exact evidence."),
    ]
    unscored = sum(entry.get("model_score") is None for entry in strings)
    if unscored:
        string_entries.append((0, f"Model scores unavailable for {unscored} extracted strings."))
    shown, omission = _pdf_limited(flagged, PDF_FINDING_LIMIT, "model-flagged strings")
    for index, entry in shown:
        score = entry.get("model_score")
        formatted_score = f"{score:.4f}" if score is not None else "unavailable"
        string_entries.append((0, f"String [{index}] at {hex(entry['offset'])}; {entry['encoding']}; "
                               f"score {formatted_score}: {_pdf_text(entry['value'])}"))
    if omission:
        string_entries.append((0, omission))
    yield "Highest-scoring flagged strings", string_entries


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
    for title, entries in pdf_report_sections(report):
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
