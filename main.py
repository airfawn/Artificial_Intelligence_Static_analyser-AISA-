#!/usr/bin/env python3
"""
Automating Static Analysis - Main CLI Entrypoint
Analyzes Windows PE files:
- Cryptographic Hashes (MD5, SHA1, SHA256)
- PE Header & Packing Heuristic (VirtualSize vs RawSize discrepancy + Entropy)
- Native Cross-Platform String Extraction (ASCII & UTF-16LE)
- Weighted Scoring Engine (Links, Paths, Sensitive APIs, RegKeys, Obfuscation)
- Crucial IOC Extraction and Rich Terminal Reporting
"""

import sys
import os
import argparse
import json
from core import PEAnalyzer, StringExtractor, StringAnalyzer
from cli import render_report


def analyze_target(file_path: str, min_string_len: int = 4, export_json: str = None):
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' does not exist.")
        sys.exit(1)

    # 1. PE Header & Packing Analysis
    pe_analyzer = PEAnalyzer(file_path)
    pe_summary = pe_analyzer.get_pe_summary()

    # 2. Native Binary String Extraction (ASCII + UTF-16LE)
    extractor = StringExtractor(min_length=min_string_len)
    raw_strings = extractor.extract_from_file(file_path)

    # 3. Weighted Heuristic & AI String Analysis
    analyzer = StringAnalyzer()
    string_analysis = analyzer.analyze_strings(raw_strings)

    # 4. Render Rich Visual Report
    render_report(pe_summary, string_analysis)

    # 5. Optional JSON Export for SOC/SIEM pipeline integration
    if export_json:
        report_data = {
            "pe_metadata": pe_summary,
            "string_analysis": string_analysis,
        }
        with open(export_json, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Full JSON triage report saved to: {export_json}")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Static Analysis Engine: PE Packing Detection, Dual-Encoding Strings, & Weighted Threat Scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", nargs="?", help="Path to Windows PE binary or file to analyze")
    parser.add_argument("-m", "--min-len", type=int, default=4, help="Minimum string length (default: 4)")
    parser.add_argument("-j", "--json", type=str, default=None, help="Export analysis report as JSON to specified path")

    args = parser.parse_args()

    if not args.file:
        parser.print_help()
        print("\n[!] Please provide a file to analyze. Example: python main.py samples/test_sample.exe")
        sys.exit(0)

    analyze_target(args.file, min_string_len=args.min_len, export_json=args.json)


if __name__ == "__main__":
    main()