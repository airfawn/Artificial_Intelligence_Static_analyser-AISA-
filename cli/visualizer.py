"""Terminal rendering for collected PE metadata, strings, and API tables."""

from typing import Any, Dict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def render_report(report: Dict[str, Any]) -> None:
    pe = report["pe_metadata"]
    console.print(Panel("STATIC PE DATA COLLECTION", box=box.DOUBLE))
    metadata = Table(title="Original file", box=box.ROUNDED)
    metadata.add_column("Property")
    metadata.add_column("Value")
    for label, value in (
        ("Path", pe["file_path"]),
        ("Size", f"{pe['file_size']:,} bytes"),
        ("Valid PE", str(pe["is_valid_pe"])),
        ("Architecture", pe["architecture"]),
        ("Subsystem", pe["subsystem"]),
        ("PE timestamp", str(pe["timestamp"])),
        ("MD5", pe["hashes"]["md5"]),
        ("SHA-1", pe["hashes"]["sha1"]),
        ("SHA-256", pe["hashes"]["sha256"]),
    ):
        metadata.add_row(label, Text(str(value)))
    console.print(metadata)

    packing = pe["packing"]
    status = "Invalid PE" if not pe["is_valid_pe"] else (
        "Likely packed" if packing["is_packed"] else "No packing indicators detected"
    )
    details = "\n".join([f"{status} (confidence: {packing['confidence']})"] + packing["reasons"])
    console.print(Panel(Text(details), title="Packing assessment"))
    packer = packing["packer"]
    names = ", ".join(match["name"] for match in packer["matches"])
    identity = packer["name"] or (f"Ambiguous: {names}" if names else "Unknown")
    prediction = packing["model"].get("prediction")
    model_detail = (
        f"\nPrediction: {prediction['label']} (centroid distance: {prediction['distance']:.4f})"
        if prediction else ""
    )
    console.print(Panel(Text(
        f"Section-name identification: {identity}\n"
        f"Packing model: {packing['model']['status']} — {packing['model']['message']}{model_detail}"
    ), title="Packer identification"))
    weighted = packing["weighted_score"]
    score = weighted["score"]
    score_detail = (
        f"{score:.2f} (above {weighted['threshold']}: {weighted['above_threshold']})"
        if score is not None else "unavailable"
    )
    console.print(Panel(Text(f"{score_detail}\n{weighted['message']}"), title="Experimental packing score"))
    if packing["sections"]:
        sections = Table(title="PE sections")
        for column in ("Name", "Virtual size", "Disk size", "Delta", "Ratio", "Entropy", "Indicators"):
            sections.add_column(column)
        for section in packing["sections"]:
            flags = [
                name for key, name in (
                    ("is_packer_name", "packer name"),
                    ("is_discrepancy_suspicious", "size discrepancy"),
                    ("is_high_entropy", "high entropy"),
                ) if section[key]
            ]
            sections.add_row(
                Text(section["name"]), str(section["virtual_size"]), str(section["raw_size"]),
                str(section["size_delta"]), str(section["discrepancy_ratio"]),
                str(section["entropy"]), ", ".join(flags) or "none",
            )
        console.print(sections)

    console.print(Panel(Text(report["unpacking"]["message"]), title="Unpacking"))
    analyzed = report.get("analyzed_file")
    if analyzed and analyzed["source"] == "unpacked":
        hashes = analyzed["hashes"]
        console.print(Panel(Text(f"MD5: {hashes['md5']}\nSHA-256: {hashes['sha256']}"),
                            title="Unpacked file hashes"))
    for error in report["errors"]:
        console.print(Panel(Text(error), title="Collection error", border_style="red"))
    if report["strings"] is None or report["apis"] is None:
        console.print("[bold yellow]Collection incomplete; strings and APIs were not collected.[/bold yellow]")
        return

    apis = report["apis"]
    console.print(Panel(Text(apis["limitations"]), title="API collection limitations"))
    for warning in apis["warnings"]:
        console.print(Panel(Text(warning), title="PE parser warning", border_style="yellow"))
    for category, title in (("imports", "Imports"), ("delay_imports", "Delay imports"), ("exports", "Exports")):
        entries = apis[category]
        status = apis["directories"][category]["status"]
        if status == "unreadable":
            console.print(Panel(Text(apis["directories"][category]["message"]),
                                title=f"{title}: unreadable", border_style="red"))
            continue
        if status == "absent":
            console.print(Panel("No directory is declared in the PE.", title=f"{title}: absent"))
            continue
        table = Table(title=f"{title}: {len(entries)} ({status})")
        for name in ("DLL", "Name", "Ordinal", "Hint", "Address", "Forwarder"):
            table.add_column(name)
        for item in entries:
            address = item.get("address_rva", item.get("address"))
            table.add_row(
                Text(str(item.get("dll") or apis.get("export_dll") or "")),
                Text(str(item.get("name") or "")),
                str(item["ordinal"]) if item.get("ordinal") is not None else "",
                str(item["hint"]) if item.get("hint") is not None else "",
                hex(address) if address is not None else "",
                Text(str(item.get("forwarder") or "")),
            )
        console.print(table)

    categorized = report["categorized_strings"]
    console.print(Panel(
        "Categories contain pattern-matched candidates, not verified behavior. "
        "Each entry references an extracted string and may occur in multiple categories.",
        title="Categorized strings",
    ))
    for key, title in (
        ("domains", "Domains"), ("file_paths", "File paths"),
        ("urls", "URLs"), ("commands", "Command-line candidates"),
    ):
        entries = categorized[key]
        category_table = Table(title=f"{title}: {len(entries)}")
        for column in ("String index", "File offset", "Encoding", "Match"):
            category_table.add_column(column)
        for item in entries:
            category_table.add_row(
                str(item["string_index"]), hex(item["string_offset"]),
                item["encoding"], Text(item["value"]),
            )
        console.print(category_table)

    strings = report["strings"]
    table = Table(title=f"Extracted strings: {len(strings)}")
    for name in ("Index", "Offset", "Encoding", "Length", "Entropy", "Model score", "Model flag", "String"):
        table.add_column(name)
    for index, entry in enumerate(strings):
        score = entry.get("model_score")
        table.add_row(
            str(index), hex(entry["offset"]), entry["encoding"], str(entry["length"]),
            str(entry["entropy"]), f"{score:.4f}" if score is not None else "unavailable",
            str(entry["model_suspicious"]) if "model_suspicious" in entry else "unavailable",
            Text(entry["value"]),
        )
    console.print(table)
    console.print("Model scores represent per-string suspiciousness, not readability or a file verdict.")
    if report["status"] != "complete":
        console.print("[bold yellow]Collection incomplete; see errors above.[/bold yellow]")
