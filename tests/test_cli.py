import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from main import main
from samples.create_sample import build_api_fixture, build_minimal_pe


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "sample.exe"
        self.path.write_bytes(build_minimal_pe())
        self.script = Path(__file__).resolve().parent.parent / "main.py"

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(self.script), *map(str, args)],
            cwd=self.directory.name, capture_output=True, text=True,
        )

    def test_help(self):
        result = self.run_cli("-h")
        self.assertEqual(result.returncode, 0)
        for option in ("-f", "-s", "-h", "--min-len", "--collect-only"):
            self.assertIn(option, result.stdout)

    def test_version_needs_no_input_or_report(self):
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "aisa v.0.50")
        self.assertEqual(sorted(p.name for p in Path(self.directory.name).iterdir()), ["sample.exe"])

    def test_file_and_save_options(self):
        destination = Path(self.directory.name) / "report.json"
        result = self.run_cli("-f", self.path, "-s", destination, "--collect-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = json.loads(destination.read_text())
        self.assertEqual(saved["status"], "complete")
        self.assertNotIn("ai_analysis", saved)
        self.assertIn(str(destination), result.stdout)
        result = self.run_cli("-f", self.path, "-s", destination, "--collect-only")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(destination.read_text())["status"], "complete")

    def test_default_and_legacy_options(self):
        result = self.run_cli("-f", self.path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.path.with_name(self.path.name + ".report.pdf").read_bytes().startswith(b"%PDF-"))
        legacy = Path(self.directory.name) / "legacy.json"
        result = self.run_cli(self.path, "-j", legacy, "--collect-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(legacy.is_file())

    def test_invalid_cli_usage(self):
        for args in ((), ("-f",), ("-s", "report.json"), ("-f", self.path, self.path)):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)

    def test_analysis_options_are_validated(self):
        output = Path(self.directory.name) / "analysis.json"
        for args in (
            ("--analyze-report", self.path),
            ("--analysis-output", output),
            ("--analyze-report", self.path, "--analysis-output", output, "-f", self.path),
            ("--analyze-report", self.path, "--analysis-output", output, "--min-len", "8"),
            ("--analyze-report", self.path, "--analysis-output", output, "--collect-only"),
            ("--analyze-report", self.path, "--analysis-output", output, "--collect-only=false"),
        ):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_incomplete_report_is_saved(self):
        self.path.write_bytes(b"not a PE")
        destination = Path(self.directory.name) / "partial.json"
        result = self.run_cli("-f", self.path, "-s", destination)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(destination.read_text())["status"], "incomplete")

    def test_collection_runs_model_and_saves_final_report(self):
        destination = Path(self.directory.name) / "final.json"
        result = {
            "status": "experimental",
            "analysis": {"hypotheses": [], "summary": "Insufficient evidence."},
            "selected_evidence": [], "limitations": [],
        }
        with patch("sys.argv", ["aisa", "-f", str(self.path), "-s", str(destination), "--collect-only=false"]), \
             patch("main.analyze_report", return_value=result) as model, \
             patch("main.render_report"), patch("main.render_ai_analysis"):
            self.assertEqual(main(), 0)
        report = json.loads(destination.read_text())
        self.assertEqual(report["ai_analysis"], result)
        self.assertEqual(model.call_args.args[0]["status"], "complete")

    def test_model_failure_preserves_collection_and_returns_error(self):
        destination = Path(self.directory.name) / "final.json"
        with patch("sys.argv", ["aisa", "-f", str(self.path), "-s", str(destination)]), \
             patch("main.analyze_report", side_effect=RuntimeError("model unavailable")), \
             patch("main.render_report"), patch("main.render_ai_analysis"):
            self.assertEqual(main(), 1)
        report = json.loads(destination.read_text())
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["ai_analysis"]["status"], "failed")
        self.assertIn("model unavailable", report["ai_analysis"]["error"])

    def test_incomplete_collection_does_not_run_model(self):
        self.path.write_bytes(b"not a PE")
        destination = Path(self.directory.name) / "partial.json"
        with patch("sys.argv", ["aisa", "-f", str(self.path), "-s", str(destination)]), \
             patch("main.analyze_report") as model, \
             patch("main.render_report"), patch("main.render_ai_analysis"):
            self.assertEqual(main(), 2)
        model.assert_not_called()
        self.assertEqual(json.loads(destination.read_text())["ai_analysis"]["status"], "skipped")

    def test_existing_output_fails_before_running_model(self):
        destination = Path(self.directory.name) / "existing.json"
        destination.write_text("existing")
        with patch("sys.argv", ["aisa", "-f", str(self.path), "-s", str(destination), "--collect-only=false"]), \
             patch("main.analyze_report") as model:
            self.assertEqual(main(), 1)
        model.assert_not_called()
        self.assertEqual(destination.read_text(), "existing")

    def test_collection_analysis_runs_offline(self):
        destination = Path(self.directory.name) / "final.json"
        with patch("sys.argv", ["aisa", "-f", str(self.path), "-s", str(destination), "--collect-only=false"]), \
             patch("socket.socket", side_effect=AssertionError("network not allowed")), \
             patch("main.render_report"), patch("main.render_ai_analysis"):
            self.assertEqual(main(), 0)
        analysis = json.loads(destination.read_text())["ai_analysis"]
        self.assertEqual(analysis["status"], "experimental")
        self.assertEqual(analysis["method"], "offline_api_frequency")

    def test_analysis_reports_collected_import_and_analyzes_saved_report(self):
        self.path.write_bytes(build_api_fixture())
        report_path = Path(self.directory.name) / "collection.json"
        result = self.run_cli("-f", self.path, "-s", report_path, "--collect-only=false")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(report_path.read_text())
        flagged = report["ai_analysis"]["flagged_imports"]
        create = next(item for item in flagged if item["name"] == "createfilew")
        self.assertEqual(create["evidence"][0]["name"], "CreateFileW")
        self.assertEqual(create["evidence"][0]["index"], 0)
        self.assertIn("CreateFileW", result.stdout)
        output = Path(self.directory.name) / "analysis.json"
        result = self.run_cli("--analyze-report", report_path, "--analysis-output", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text()), report["ai_analysis"])

    def test_default_runs_api_analysis(self):
        self.path.write_bytes(build_api_fixture())
        output = Path(self.directory.name) / "report.json"
        result = self.run_cli("-f", self.path, "-s", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        analysis = json.loads(output.read_text())["ai_analysis"]
        self.assertEqual(analysis["status"], "experimental")
        self.assertTrue(any(item["name"] == "createfilew" for item in analysis["flagged_imports"]))

    def test_collection_only_explicit_values(self):
        for value in ("true", "TRUE"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "report.json"
                args = ["aisa", "-f", str(self.path), "-s", str(output)]
                args += ["--collect-only", value]
                with patch("sys.argv", args), patch("main.analyze_report") as model, \
                     patch("main.render_report"):
                    self.assertEqual(main(), 0)
                model.assert_not_called()
                self.assertNotIn("ai_analysis", json.loads(output.read_text()))
        self.assertEqual(self.run_cli("-f", self.path, "--collect-only=invalid").returncode, 2)


if __name__ == "__main__":
    unittest.main()
