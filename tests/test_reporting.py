import base64
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from cli.reporting import write_pdf_report, write_text_report
from cli.visualizer import render_ai_analysis, render_report
from core.api_analysis import analyze_report
from core.workflow import analyze_file
from main import analyze_target
from samples.create_sample import build_api_fixture, build_minimal_pe


class TestReporting(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "sample.exe"
        self.path.write_bytes(
            build_minimal_pe() + b"\0low-marker\0high-marker https://example.org\0"
        )

    def ranked_report(self):
        class Model:
            def __init__(self, model_file):
                pass

            def predict_suspiciousness(self, text):
                return (0.9, True) if "high-marker" in text else (0.1, False)

        with patch("core.workflow.StringClassifierModel", Model):
            return analyze_file(str(self.path))

    def test_ranked_output_preserves_evidence_indices(self):
        report = self.ranked_report()
        original = [item["value"] for item in report["strings"]]
        text = io.StringIO()
        write_text_report(report, text)
        self.assertLess(text.getvalue().index("high-marker"), text.getvalue().index("low-marker"))
        output = io.StringIO()
        with patch("cli.visualizer.console", Console(file=output, width=180)):
            render_report(report)
        self.assertLess(output.getvalue().rindex("high-marker"), output.getvalue().rindex("low-marker"))
        self.assertEqual(original, [item["value"] for item in report["strings"]])
        domain = report["categorized_strings"]["domains"][0]
        self.assertIn(domain["value"], report["strings"][domain["string_index"]]["value"])

    def test_json_ranking_and_unscored_entries(self):
        report = self.ranked_report()
        report["strings"][0].pop("model_score")
        destination = self.path.with_suffix(".json")
        with patch("main.analyze_file", return_value=report), patch("main.render_report"):
            result = analyze_target(str(self.path), output=str(destination), format="json")
        saved = json.loads(destination.read_text())
        indices = saved["ranked_string_indices"]
        self.assertEqual(indices[-1], 0)
        scores = [saved["strings"][index]["model_score"] for index in indices[:-1]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(saved, result)

    def test_pdf_contains_ranked_evidence_and_limitations(self):
        report = self.ranked_report()
        output = io.BytesIO()
        write_pdf_report(report, output)
        pdf = output.getvalue()
        self.assertTrue(pdf.startswith(b"%PDF-"))
        streams = re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.DOTALL)
        decoded = b"".join(zlib.decompress(base64.a85decode(b"<~" + stream, adobe=True))
                           for stream in streams)
        for expected in (b"STATIC ANALYSIS REPORT", b"Executive summary", b"SHA-256",
                         b"Highest-scoring flagged strings", b"high-marker",
                         b"not proof of maliciousness", b"Not performed.",
                         b"--collect-only=false"):
            self.assertIn(expected, decoded)
        self.assertNotIn(b"low-marker", decoded)

    def test_pdf_limits_large_collections_but_text_keeps_full_evidence(self):
        report = self.ranked_report()
        report["strings"] = [
            {"value": f"marker-{index:05d}-" + "x" * 1000, "offset": index,
             "encoding": "ASCII", "length": 1013, "entropy": 1.0,
             "model_score": index / 30000, "model_suspicious": True}
            for index in range(30000)
        ]
        report["categorized_strings"] = {
            "domains": [], "file_paths": [], "urls": [], "commands": [],
        }
        output = io.BytesIO()
        write_pdf_report(report, output)
        pdf = output.getvalue()
        pages = len(re.findall(rb"/Type\s*/Page\b", pdf))
        self.assertLessEqual(pages, 5)
        streams = re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.DOTALL)
        decoded = b"".join(zlib.decompress(base64.a85decode(b"<~" + stream, adobe=True))
                           for stream in streams)
        self.assertIn(b"marker-29999", decoded)
        self.assertNotIn(b"marker-00000", decoded)
        self.assertIn(b"29980 additional model-flagged strings omitted", decoded)
        self.assertIn(b"truncated; see full report", decoded)
        text = io.StringIO()
        write_text_report(report, text)
        self.assertIn("marker-00000", text.getvalue())

    def test_pdf_includes_flagged_api_and_evidence_when_analysis_enabled(self):
        self.path.write_bytes(build_api_fixture())
        report = analyze_file(str(self.path))
        report["ai_analysis"] = analyze_report(report)
        output = io.BytesIO()
        write_pdf_report(report, output)
        streams = re.findall(rb"stream\r?\n(.*?)endstream", output.getvalue(), re.DOTALL)
        decoded = b"".join(zlib.decompress(base64.a85decode(b"<~" + stream, adobe=True))
                           for stream in streams)
        self.assertIn(b"createfilew", decoded)
        self.assertIn(b"imports[0]", decoded)
        self.assertIn(b"CreateFileW", decoded)
        self.assertNotIn(b"Not performed.", decoded)

    def test_default_cli_pdf_includes_flagged_api(self):
        self.path.write_bytes(build_api_fixture())
        script = Path(__file__).resolve().parents[1] / "main.py"
        result = subprocess.run([sys.executable, str(script), str(self.path)],
                                capture_output=True, text=True, cwd=self.temporary.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        pdf = self.path.with_name(self.path.name + ".report.pdf").read_bytes()
        streams = re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.DOTALL)
        decoded = b"".join(zlib.decompress(base64.a85decode(b"<~" + stream, adobe=True))
                           for stream in streams)
        self.assertIn(b"CreateFileW", decoded)
        self.assertNotIn(b"Not performed.", decoded)

    def test_pdf_reports_incomplete_collection_and_unavailable_scores(self):
        report = self.ranked_report()
        report["status"] = "incomplete"
        report["errors"] = ["Cannot load trained model"]
        report["ai_analysis"] = {"status": "skipped", "message": "Collection incomplete."}
        for item in report["strings"]:
            item.pop("model_score")
            item.pop("model_suspicious")
        output = io.BytesIO()
        write_pdf_report(report, output)
        streams = re.findall(rb"stream\r?\n(.*?)endstream", output.getvalue(), re.DOTALL)
        decoded = b"".join(zlib.decompress(base64.a85decode(b"<~" + stream, adobe=True))
                           for stream in streams)
        self.assertIn(b"Cannot load trained model", decoded)
        self.assertIn(b"Status: skipped", decoded)
        self.assertIn(b"Model scores unavailable", decoded)

    def test_family_labels_are_red_without_interpreting_markup(self):
        result = {
            "status": "experimental",
            "flagged_imports": [{
                "evidence": [{"table": "imports", "index": 0, "name": "X"}],
                "suggestion": "possible", "malware_reports": 1, "malware_total": 1,
                "benign_reports": 0, "benign_total": 1,
                "weak_family_counts": [{"label": "[family]", "count": 1, "samples": 1}],
            }],
            "patterns": [], "observed_associations": [], "summary": "summary", "limitations": [],
        }
        output = io.StringIO()
        with patch("cli.visualizer.console", Console(file=output, force_terminal=True, width=160)):
            render_ai_analysis(result)
        self.assertIn("\x1b[1;31m", output.getvalue())
        self.assertIn("[family]", output.getvalue())

    def test_packing_only_does_not_run_other_collectors(self):
        self.path.write_bytes(build_minimal_pe(packed=True))
        destination = self.path.with_suffix(".json")
        with patch("core.workflow.StringExtractor.extract_from_bytes", side_effect=AssertionError), \
             patch("core.workflow.collect_api_tables", side_effect=AssertionError), \
             patch("core.workflow.subprocess.run", side_effect=AssertionError), \
             patch("main.render_report"):
            report = analyze_target(str(self.path), mode="packing", format="json", output=str(destination))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["pe_metadata"]["packing"]["model"]["status"], "trained")
        self.assertTrue(report["pe_metadata"]["packing"]["is_packed"])
        self.assertNotIn("strings", report)
        self.assertEqual(json.loads(destination.read_text()), report)

    def test_packing_model_failure_is_visible_and_incomplete(self):
        destination = self.path.with_suffix(".json")
        with patch("core.packing_model.MODEL_PATH", self.path.with_name("missing-model.json")), \
             patch("main.render_report"):
            report = analyze_target(str(self.path), mode="packing", format="json", output=str(destination))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["pe_metadata"]["packing"]["model"]["status"], "unavailable")
        self.assertIn("Cannot load packing model", report["errors"][0])

    def test_cli_formats_modes_and_incomplete_packing(self):
        script = Path(__file__).resolve().parents[1] / "main.py"

        def run(*args):
            return subprocess.run([sys.executable, str(script), *map(str, args)],
                                  capture_output=True, text=True, cwd=self.temporary.name)

        text = Path(self.temporary.name) / "packing.txt"
        self.assertEqual(run("-p", self.path, "-format=text", "-s", text).returncode, 0)
        self.assertIn("Packing assessment only", text.read_text())
        self.assertNotIn("Extracted strings", text.read_text())
        self.assertEqual(run("-a", "-p", self.path).returncode, 2)
        self.assertEqual(run("-p", self.path, "--collect-only=false").returncode, 2)
        self.assertEqual(run("-j", text, "--format=pdf", self.path).returncode, 2)
        self.path.write_bytes(b"invalid")
        result = run("-p", self.path, "--format=json")
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(self.path.with_name(self.path.name + ".report.json").read_text())
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("not a valid", report["errors"][0])


if __name__ == "__main__":
    unittest.main()
