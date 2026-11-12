"""Verify that a frozen AISA build can load its model and analyze a PE."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from samples.create_sample import build_minimal_pe


def main():
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="aisa-smoke-") as directory:
        sample = Path(directory) / "sample.exe"
        report_path = Path(directory) / "report.json"
        sample.write_bytes(build_minimal_pe())
        subprocess.run([str(executable), "-h"], check=True, cwd=directory)
        subprocess.run(
            [str(executable), "-f", str(sample), "-s", str(report_path)],
            check=True,
            cwd=directory,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report["status"] != "complete" or not report["strings"]:
            raise RuntimeError(f"Incomplete or empty collection report: {report['errors']}")
        if not all("model_score" in entry for entry in report["strings"]):
            raise RuntimeError("The packaged model did not score the extracted strings.")
        if report["pe_metadata"]["packing"]["model"]["status"] != "trained":
            raise RuntimeError("The packaged packing model could not be loaded.")
        if not report["pe_metadata"]["hashes"].get("sha256"):
            raise RuntimeError("The packaged analyzer did not produce a SHA-256 hash.")
        analysis_path = Path(directory) / "analysis.json"
        subprocess.run(
            [str(executable), "--analyze-report", str(report_path),
             "--analysis-output", str(analysis_path)],
            check=True, cwd=directory, timeout=600,
        )
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        if analysis["status"] != "experimental" or analysis["model"] != "qwen3:1.7b":
            raise RuntimeError("The bundled model did not produce an experimental analysis.")
        if analysis["source_sha256"] != report["pe_metadata"]["hashes"]["sha256"]:
            raise RuntimeError("The analysis does not reference the collected report.")


if __name__ == "__main__":
    main()
