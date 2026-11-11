#!/usr/bin/env python3
"""Packing-first PE data collection CLI."""

import os
import argparse
import json
import sys
from pathlib import Path
from core.workflow import analyze_file
from cli import render_report


def analyze_target(file_path: str, min_string_len: int = 4, export_json: str = None):
    if export_json and (
        os.path.realpath(export_json) == os.path.realpath(file_path)
        or (os.path.exists(export_json) and os.path.exists(file_path) and os.path.samefile(export_json, file_path))
    ):
        raise ValueError("JSON output must not overwrite the input file")
    report_data = analyze_file(file_path, min_string_len=min_string_len)
    if export_json:
        destination = Path(export_json)
        with destination.open("x", encoding="utf-8") as file:
            json.dump(report_data, file, indent=2, ensure_ascii=True)
    else:
        input_path = Path(file_path).absolute()
        counter = 0
        while True:
            suffix = f".report.{counter}.json" if counter else ".report.json"
            destination = input_path.with_name(input_path.name + suffix)
            try:
                with destination.open("x", encoding="utf-8") as file:
                    json.dump(report_data, file, indent=2, ensure_ascii=True)
                break
            except FileExistsError:
                counter += 1
    render_report(report_data)
    print(f"[+] Collection report saved to: {destination}")
    return report_data


def main():
    parser = argparse.ArgumentParser(
        prog="aisa",
        description="Collect PE packing information, strings, static API tables, and file hashes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", nargs="?", help="Path to Windows PE binary (alternative to -f)")
    parser.add_argument("-f", "--file", dest="file_option", help="Path to Windows PE binary to analyze")
    parser.add_argument("-m", "--min-len", type=int, default=4, help="Minimum string length (default: 4)")
    parser.add_argument("-s", "--save", "-j", "--json", dest="json", type=str, default=None,
                        help="Save JSON report to a new file (default: beside input)")

    args = parser.parse_args()

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
        report = analyze_target(file_path, min_string_len=args.min_len, export_json=args.json)
    except (OSError, ValueError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    sys.exit(main())