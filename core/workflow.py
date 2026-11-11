"""Packing-first PE triage workflow."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict

from .ml_model import StringClassifierModel
from .api_extractor import collect_api_tables
from .pe_analyzer import PEAnalyzer
from .string_categories import categorize_strings
from .string_extractor import StringExtractor


MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "string_model_weights.json"
UPX_TIMEOUT_SECONDS = 60


def find_upx():
    if getattr(sys, "frozen", False):
        bundled = Path(sys.executable).resolve().parent / "upx" / "upx.exe"
        if bundled.is_file():
            return str(bundled)
    return shutil.which("upx")


def analyze_file(file_path: str, min_string_len: int = 4) -> Dict[str, Any]:
    """Analyze strings only after a valid PE passes the packing gate."""
    if min_string_len < 1:
        raise ValueError("Minimum string length must be positive")
    original = PEAnalyzer(file_path)
    pe_summary = original.get_pe_summary(include_dropper=False)
    report: Dict[str, Any] = {
        "pe_metadata": pe_summary,
        "unpacking": {"status": "not_needed", "message": "No packing indicators detected."},
        "strings": None,
        "categorized_strings": None,
        "apis": None,
        "errors": [],
        "status": "incomplete",
    }

    if not original.is_valid_pe:
        report["unpacking"] = {"status": "not_attempted", "message": "Input is not a valid Windows PE."}
        return report

    def finish(analyzer: PEAnalyzer) -> None:
        assert analyzer.pe is not None
        strings = StringExtractor(min_length=min_string_len).extract_from_bytes(analyzer.file_bytes)
        report["strings"] = strings
        report["categorized_strings"] = categorize_strings(strings)
        report["apis"] = collect_api_tables(analyzer.pe)
        report["analyzed_file"] = {
            "source": "unpacked" if analyzer is not original else "original",
            "file_size": len(analyzer.file_bytes),
            "hashes": analyzer.hashes,
            "packing": analyzer.analyze_packing(),
        }
        for name, info in report["apis"]["directories"].items():
            if info["status"] == "unreadable":
                report["errors"].append(info["message"])
        try:
            if not MODEL_PATH.is_file():
                raise FileNotFoundError(f"Trained model weights not found: {MODEL_PATH}")
            model = StringClassifierModel(model_file=str(MODEL_PATH))
        except (OSError, ValueError) as exc:
            report["errors"].append(f"Cannot load trained model: {exc}")
            return

        for entry in strings:
            score, flagged = model.predict_suspiciousness(entry["value"])
            entry["model_score"] = score
            entry["model_suspicious"] = flagged
        if not report["errors"]:
            report["status"] = "complete"

    packing = pe_summary["packing"]
    if not packing["is_packed"]:
        finish(original)
        return report

    names = [section["name"].lower() for section in packing["sections"]]
    is_upx = any(name.startswith(("upx0", "upx1", "upx2", ".upx")) for name in names)
    if not is_upx:
        report["unpacking"] = {
            "status": "unsupported",
            "message": "Unsupported packer; provide an unpacked file to collect strings and APIs.",
        }
        return report

    upx = find_upx()
    if not upx:
        report["unpacking"] = {
            "status": "unavailable",
            "message": "UPX is not installed or not on PATH; provide an unpacked file.",
        }
        return report

    with tempfile.TemporaryDirectory(prefix="static-analysis-upx-") as directory:
        input_copy = os.path.join(directory, "input.exe")
        output = os.path.join(directory, "unpacked.exe")
        try:
            with open(input_copy, "wb") as file:
                file.write(original.file_bytes)
            result = subprocess.run(
                [upx, "-d", "-o", output, input_copy],
                capture_output=True, text=True, errors="replace", timeout=UPX_TIMEOUT_SECONDS, check=False,
            )
        except subprocess.TimeoutExpired:
            report["unpacking"] = {"status": "failed", "message": "UPX timed out; provide an unpacked file."}
            return report
        except OSError as exc:
            report["unpacking"] = {"status": "failed", "message": f"Unable to run UPX: {exc}; provide an unpacked file."}
            return report
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:1000]
            report["unpacking"] = {
                "status": "failed",
                "message": f"UPX failed (exit {result.returncode}): {detail or 'no diagnostic output'}; provide an unpacked file.",
            }
            return report
        if not os.path.isfile(output):
            report["unpacking"] = {"status": "failed", "message": "UPX produced no output; provide an unpacked file."}
            return report
        try:
            unpacked = PEAnalyzer(output)
        except OSError as exc:
            report["unpacking"] = {"status": "failed", "message": f"Cannot read UPX output: {exc}; provide an unpacked file."}
            return report
        if not unpacked.is_valid_pe or unpacked.analyze_packing()["is_packed"]:
            report["unpacking"] = {
                "status": "failed",
                "message": "UPX output is invalid or still appears packed; provide an unpacked file.",
            }
            return report
        report["unpacking"] = {"status": "success", "message": "UPX output passed PE and packing checks."}
        finish(unpacked)
    return report
