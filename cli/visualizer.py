"""
Rich Terminal Visualizer for Static Analysis.
Renders panels, tables, and color-coded security scorecards.
"""

from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def render_report(pe_summary: Dict[str, Any], string_analysis: Dict[str, Any]):
    """Renders the comprehensive static analysis triage report to the terminal."""
    console.print()

    # 1. Header Banner
    banner = Text("  AUTOMATED STATIC ANALYSIS ENGINE  ", style="bold white on blue")
    console.print(Panel(banner, style="cyan", box=box.DOUBLE))

    # 2. File Metadata & Hashes Table
    meta_table = Table(title="Binary Metadata & Hashes", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    meta_table.add_column("Property", style="bold yellow", width=22)
    meta_table.add_column("Value", style="white")

    meta_table.add_row("Target File", str(pe_summary.get("file_path", "N/A")))
    meta_table.add_row("File Size", f"{pe_summary.get('file_size', 0):,} bytes")
    meta_table.add_row("Valid Windows PE", "Yes" if pe_summary.get("is_valid_pe") else "No")
    meta_table.add_row("Architecture", str(pe_summary.get("architecture", "Unknown")))
    meta_table.add_row("Subsystem", str(pe_summary.get("subsystem", "Unknown")))

    hashes = pe_summary.get("hashes", {})
    meta_table.add_row("MD5 Hash", hashes.get("md5", "N/A"))
    meta_table.add_row("SHA-256 Hash", hashes.get("sha256", "N/A"))
    console.print(meta_table)

    # 3. PE Header & Packing Analysis Table
    packing = pe_summary.get("packing", {})
    is_packed = packing.get("is_packed", False)
    pack_status = "[bold red]PACKED[/bold red]" if is_packed else "[bold green]UNPACKED[/bold green]"
    confidence = packing.get("confidence", "N/A")

    pack_panel_content = Text()
    pack_panel_content.append("Packing Assessment: ", style="bold")
    pack_panel_content.append(f"{pack_status} (Confidence: {confidence})\n", style="bold")
    for r in packing.get("reasons", []):
        pack_panel_content.append(f"  • {r}\n", style="italic")

    console.print(Panel(pack_panel_content, title="PE Header & Packing Detection", border_style="red" if is_packed else "green"))

    # Sections detail table
    sections = packing.get("sections", [])
    if sections:
        sec_table = Table(title="PE Section Geometry & Entropy Analysis", box=box.SIMPLE_HEAD, show_header=True, header_style="bold magenta")
        sec_table.add_column("Section", style="bold")
        sec_table.add_column("Virtual Size", justify="right")
        sec_table.add_column("Raw Size", justify="right")
        sec_table.add_column("Delta (V - R)", justify="right")
        sec_table.add_column("Ratio (V/R)", justify="right")
        sec_table.add_column("Entropy", justify="right")
        sec_table.add_column("Flags / Status", style="yellow")

        for sec in sections:
            flags = []
            if sec.get("is_packer_name"):
                flags.append("[red]Packer Signature[/red]")
            if sec.get("is_discrepancy_suspicious"):
                flags.append("[red]Size Anomaly[/red]")
            if sec.get("is_high_entropy"):
                flags.append("[yellow]High Entropy (>7.0)[/yellow]")
            if not flags:
                flags.append("[green]Normal[/green]")

            sec_table.add_row(
                sec["name"],
                f"0x{sec['virtual_size']:X} ({sec['virtual_size']:,})",
                f"0x{sec['raw_size']:X} ({sec['raw_size']:,})",
                f"{sec['size_delta']:,}",
                f"{sec['discrepancy_ratio']}x",
                f"{sec['entropy']:.2f}",
                ", ".join(flags),
            )
        console.print(sec_table)

    # 4. Strings & Weighted Model Findings
    total_strings = string_analysis.get("total_strings_count", 0)
    suspicious_count = string_analysis.get("suspicious_count", 0)
    risk_score = string_analysis.get("total_risk_score", 0)

    # Calculate Threat Level
    if risk_score >= 120 or (is_packed and risk_score >= 60):
        threat_badge = "[bold white on red] CRITICAL RISK [/bold white on red]"
    elif risk_score >= 60:
        threat_badge = "[bold black on yellow] HIGH SUSPICION [/bold black on yellow]"
    elif risk_score >= 20:
        threat_badge = "[bold black on cyan] MODERATE SUSPICION [/bold black on cyan]"
    else:
        threat_badge = "[bold white on green] LOW / BENIGN [/bold white on green]"

    summary_text = (
        f"Total Strings Extracted: [bold]{total_strings:,}[/bold] | "
        f"Suspicious Strings Flagged: [bold red]{suspicious_count}[/bold red] | "
        f"Aggregate String Risk Score: [bold yellow]{risk_score}[/bold yellow] | "
        f"Verdict: {threat_badge}"
    )
    console.print(Panel(summary_text, title="Crucial String Evaluation & Weighted Model", border_style="yellow"))

    # Suspicious Strings Table
    top_strings = string_analysis.get("top_suspicious_strings", [])
    if top_strings:
        str_table = Table(title=f"Flagged Crucial Strings (Top {min(len(top_strings), 25)})", box=box.ROUNDED, header_style="bold blue")
        str_table.add_column("Weight", justify="center", style="bold red", width=8)
        str_table.add_column("Category", style="cyan", width=22)
        str_table.add_column("Encoding", style="magenta", width=10)
        str_table.add_column("Offset", style="dim", width=10)
        str_table.add_column("String Value", style="white", max_width=40, overflow="fold")
        str_table.add_column("Detection Reasons", style="dim italic", max_width=45, overflow="fold")

        for item in top_strings[:25]:
            reasons_str = "; ".join(item.get("reasons", []))
            str_table.add_row(
                str(item["weight"]),
                item["category"],
                item["encoding"],
                str(item["offset"]),
                item["value"],
                reasons_str,
            )
        console.print(str_table)

    # 5. Categorized IOC Summary Panel
    iocs = string_analysis.get("iocs", {})
    ioc_text = Text()

    for category_name, ioc_list in [
        ("Network Links & C2 IPs (Instant Suspicious)", iocs.get("urls_and_ips", [])),
        ("Directory Paths (High Suspicious)", iocs.get("paths", [])),
        ("Sensitive / Dangerous APIs", iocs.get("sensitive_apis", [])),
        ("Shell / Execution LOLBins", iocs.get("commands", [])),
        ("Persistence Registry Keys", iocs.get("registry_keys", [])),
        ("Obfuscated / Base64 Candidates", iocs.get("obfuscated", [])),
    ]:
        if ioc_list:
            ioc_text.append(f"\n[+] {category_name} ({len(ioc_list)} found):\n", style="bold yellow")
            for entry in ioc_list[:10]:
                ioc_text.append(f"    • {entry}\n", style="white")
            if len(ioc_list) > 10:
                ioc_text.append(f"    ... and {len(ioc_list) - 10} more\n", style="dim")

    if ioc_text.plain.strip():
        console.print(Panel(ioc_text, title="Extracted Indicators of Compromise (IOCs)", border_style="cyan"))

    console.print()
