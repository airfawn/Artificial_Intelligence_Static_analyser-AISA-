"""Verify that a frozen AISA build can load its model and analyze a PE."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aisa_version import __version__
from samples.create_sample import build_api_fixture


def main():
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="aisa-smoke-") as directory:
        sample = Path(directory) / "sample.bin"
        report_path = Path(directory) / "report.json"
        collection_path = Path(directory) / "collection.json"
        analysis_path = Path(directory) / "analysis.json"
        sample.write_bytes(build_api_fixture())
        version = subprocess.run([str(executable), "--version"], check=True,
                                 capture_output=True, text=True, cwd=directory)
        if version.stdout.strip() != f"aisa v.{__version__}":
            raise RuntimeError(f"Incorrect packaged version: {version.stdout!r}")
        subprocess.run([str(executable), "-h"], check=True, cwd=directory)
        subprocess.run(
            [str(executable), "-p", str(sample)], check=True, cwd=directory, timeout=120,
        )
        if not sample.with_name(sample.name + ".report.pdf").read_bytes().startswith(b"%PDF-"):
            raise RuntimeError("The packaged analyzer did not produce a PDF report.")
        subprocess.run(
            [str(executable), "-f", str(sample), "-s", str(collection_path)],
            check=True, cwd=directory, timeout=120,
        )
        collection = json.loads(collection_path.read_text(encoding="utf-8"))
        if collection["status"] != "complete" or "ai_analysis" in collection:
            raise RuntimeError("Default CLI behavior did not produce collection only.")
        subprocess.run(
            [str(executable), "-f", str(sample), "-s", str(report_path), "--collect-only=false"],
            check=True,
            cwd=directory, timeout=120,
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
        analysis = report["ai_analysis"]
        if analysis["status"] != "experimental" or analysis["method"] != "offline_api_frequency":
            raise RuntimeError("The bundled API model did not produce an experimental analysis.")
        if analysis["source_sha256"] != report["pe_metadata"]["hashes"]["sha256"]:
            raise RuntimeError("The analysis does not reference the collected report.")
        if not any(item["name"] == "createfilew" and item["evidence"][0]["index"] == 0
                   for item in analysis["flagged_imports"]):
            raise RuntimeError("The API model did not flag the synthetic import.")
        subprocess.run(
            [str(executable), "--analyze-report", str(collection_path),
             "--analysis-output", str(analysis_path)],
            check=True, cwd=directory, timeout=120,
        )
        if json.loads(analysis_path.read_text(encoding="utf-8")) != analysis:
            raise RuntimeError("Separate report analysis differs from combined analysis.")

        import pip
        fixture = Path(pip.__file__).parent / "_vendor" / "distlib" / "t32.exe"
        if not fixture.is_file():
            raise RuntimeError("pip's Windows PE fixture is unavailable for the UPX smoke test.")
        bundled_upx = executable.parent / "upx" / ("upx.exe" if sys.platform == "win32" else "upx")
        packed_path = Path(directory) / "packed.exe"
        packed_report = Path(directory) / "packed.json"
        subprocess.run([str(bundled_upx), "-o", str(packed_path), str(fixture)],
                       check=True, cwd=directory, timeout=120, capture_output=True)
        env = os.environ.copy()
        env["PATH"] = ""
        result = subprocess.run([str(executable), str(packed_path), "--json", str(packed_report)],
                                cwd=directory, timeout=120, capture_output=True, text=True, env=env)
        if result.returncode:
            raise RuntimeError(f"Bundled UPX collection failed: {result.stderr}\n{result.stdout}")
        if json.loads(packed_report.read_text(encoding="utf-8"))["unpacking"]["status"] != "success":
            raise RuntimeError("The packaged analyzer did not unpack the UPX fixture.")


if __name__ == "__main__":
    main()
