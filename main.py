#!/usr/bin/env python3
"""Packing-first PE data collection CLI."""

import os
import argparse
import json
import sys
from pathlib import Path
from aisa_version import __version__
from core.api_analysis import analyze_report, main as analysis_main
from core.workflow import analyze_file, analyze_packing_only
from cli import render_ai_analysis, render_report
from cli.reporting import write_pdf_report, write_text_report
from cli.visualizer import ranked_strings


def parse_bool(value):
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def analyze_target(file_path: str, min_string_len: int = 4, export_json: str = None,
                   include_ai: bool = False, format: str = "pdf", mode: str = "all",
                   output: str = None):
    if format not in ("pdf", "json", "text"):
        raise ValueError(f"Unsupported report format: {format}")
    if mode not in ("all", "packing"):
        raise ValueError(f"Unsupported analysis mode: {mode}")
    if export_json and output:
        raise ValueError("Provide only one output path")
    if export_json:
        format, output = "json", export_json
    if mode == "packing" and include_ai:
        raise ValueError("Offline API analysis is not available in packing-only mode")
    if output and (
        os.path.realpath(output) == os.path.realpath(file_path)
        or (os.path.exists(output) and os.path.exists(file_path) and os.path.samefile(output, file_path))
    ):
        raise ValueError("Report output must not overwrite the input file")
    if output and Path(output).exists():
        raise FileExistsError(f"Output already exists: {output}")
    report_data = (analyze_packing_only(file_path) if mode == "packing"
                   else analyze_file(file_path, min_string_len=min_string_len))
    if report_data.get("strings") is not None:
        report_data["ranked_string_indices"] = [
            index for index, _ in ranked_strings(report_data["strings"])
        ]
    if include_ai:
        if report_data["status"] != "complete":
            report_data["ai_analysis"] = {
                "status": "skipped",
                "message": "AI analysis requires a complete collection report.",
            }
        else:
            try:
                report_data["ai_analysis"] = analyze_report(report_data)
            except (OSError, ValueError, RuntimeError) as exc:
                report_data["ai_analysis"] = {"status": "failed", "error": str(exc)}
    input_path = Path(file_path).absolute()
    extension = "txt" if format == "text" else format
    counter = 0
    while True:
        suffix = f".report.{counter}.{extension}" if counter else f".report.{extension}"
        destination = Path(output) if output else input_path.with_name(input_path.name + suffix)
        try:
            if format == "pdf":
                with destination.open("xb") as file:
                    write_pdf_report(report_data, file)
            else:
                with destination.open("x", encoding="utf-8") as file:
                    if format == "json":
                        json.dump(report_data, file, indent=2, ensure_ascii=True)
                    else:
                        write_text_report(report_data, file)
            break
        except FileExistsError:
            if output:
                raise
            counter += 1
    render_report(report_data)
    if include_ai:
        render_ai_analysis(report_data["ai_analysis"])
    print(f"[+] Collection report saved to: {destination}")
    return report_data


def main():
    parser = argparse.ArgumentParser(
        prog="aisa",
        description="Collect PE packing information, strings, static API tables, and file hashes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s v.{__version__}")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("-a", "--all", action="store_true", help="Collect all data (default)")
    modes.add_argument("-p", "--packing", action="store_true", help="Assess packing only")
    parser.add_argument("file", nargs="?", help="Path to Windows PE binary (alternative to -f)")
    parser.add_argument("-f", "--file", dest="file_option", help="Path to Windows PE binary to analyze")
    parser.add_argument("-m", "--min-len", type=int, default=4, help="Minimum string length (default: 4)")
    parser.add_argument("-s", "--save", help="Save report to a new file; defaults to JSON for compatibility")
    parser.add_argument("-j", "--json", help="Save a JSON report to a new file (legacy option)")
    parser.add_argument("-format", "--format", choices=("pdf", "json", "text"), default=None,
                        help="Report format (default: pdf; -s without a format retains JSON)")
    parser.add_argument("--analyze-report", help="Run offline API analysis on an existing report")
    parser.add_argument("--analysis-output", help="New output JSON path for --analyze-report")
    parser.add_argument("--collect-only", nargs="?", const=True, default=None, type=parse_bool,
                        metavar="{true,false}",
                        help="Collect only (default: false); use true to skip offline API analysis")

    args = parser.parse_args()

    if args.analyze_report:
        if (args.file or args.file_option or args.json or args.save or args.format or args.all or args.packing
                or args.min_len != 4 or args.collect_only is not None):
            parser.error("--analyze-report cannot be combined with PE collection options")
        if not args.analysis_output:
            parser.error("--analyze-report requires --analysis-output")
        return analysis_main([args.analyze_report, "--output", args.analysis_output])
    if args.analysis_output:
        parser.error("--analysis-output requires --analyze-report")
    if args.save and args.json:
        parser.error("provide only one report output path")
    if args.json and args.format and args.format != "json":
        parser.error("--json requires JSON format")
    if args.packing and args.collect_only is False:
        parser.error("--collect-only=false is not available in packing-only mode")
    if args.file and args.file_option:
        parser.error("provide the input file either positionally or with -f, not both")
    file_path = args.file_option or args.file
    if not file_path:
        parser.print_help()
        print("\n[!] Please provide a file to analyze. Example: aisa -f samples/test_sample.exe")
        return 2

    if args.min_len < 1:
        parser.error("--min-len must be positive")
    try:
        report = analyze_target(
            file_path, min_string_len=args.min_len, export_json=args.json,
            output=args.save, format=args.format or ("json" if args.save or args.json else "pdf"),
            mode="packing" if args.packing else "all",
            include_ai=not args.packing and args.collect_only is not True,
        )
    except (OSError, ValueError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1
    if report["status"] != "complete":
        return 2
    if report.get("ai_analysis", {}).get("status") == "failed":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())