import json
import io
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.console import Console
from cli.visualizer import render_report
from core.ml_model import StringClassifierModel, StringFeatureExtractor
from core.string_analyzer import StringAnalyzer
from core.workflow import analyze_file, find_upx
from main import analyze_target
from samples.create_sample import build_minimal_pe


class TestPackingFirstWorkflow(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "sample.exe"
        self.unpacked = build_minimal_pe(packed=False)
        self.packed = build_minimal_pe(packed=True)

    def write_sample(self, contents):
        self.path.write_bytes(contents)
        return str(self.path)

    def test_bundled_upx_is_used_without_path(self):
        executable = Path(self.directory.name) / "aisa.exe"
        upx = executable.parent / "upx" / "upx.exe"
        upx.parent.mkdir()
        upx.write_bytes(b"placeholder")
        with patch.object(sys, "platform", "win32"), patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", str(executable)), \
             patch("core.workflow.shutil.which", return_value=None):
            self.assertEqual(find_upx(), str(upx.resolve()))

    def test_packed_file_uses_bundled_upx(self):
        path = self.write_sample(self.packed)
        executable = Path(self.directory.name) / "aisa.exe"
        upx = executable.parent / "upx" / "upx.exe"
        upx.parent.mkdir()
        upx.write_bytes(b"placeholder")

        def fake_upx(command, **kwargs):
            self.assertEqual(command[0], str(upx.resolve()))
            Path(command[3]).write_bytes(self.unpacked)
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(sys, "platform", "win32"), patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", str(executable)), \
             patch("core.workflow.shutil.which", return_value=None), \
             patch("core.workflow.subprocess.run", side_effect=fake_upx):
            report = analyze_file(path)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["unpacking"]["status"], "success")

    def test_missing_bundled_upx_falls_back_to_path(self):
        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", str(Path(self.directory.name) / "aisa.exe")), \
             patch("core.workflow.shutil.which", return_value="system-upx"):
            self.assertEqual(find_upx(), "system-upx")

    def test_macos_uses_bundled_upx_without_path(self):
        executable = Path(self.directory.name) / "aisa"
        upx = executable.parent / "upx" / "upx"
        upx.parent.mkdir()
        upx.write_bytes(b"placeholder")
        with patch.object(sys, "platform", "darwin"), patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", str(executable)), \
             patch("core.workflow.shutil.which", return_value=None):
            self.assertEqual(find_upx(), str(upx.resolve()))

    def test_unpacked_pe_collects_all_strings_with_model_scores(self):
        path = self.write_sample(self.unpacked)
        report = analyze_file(path)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["unpacking"]["status"], "not_needed")
        self.assertGreater(len(report["strings"]), 0)
        self.assertTrue(all("model_score" in item for item in report["strings"]))
        self.assertNotIn("string_analysis", report)
        self.assertEqual(report["analyzed_file"]["hashes"], report["pe_metadata"]["hashes"])

    def test_missing_upx_skips_strings(self):
        path = self.write_sample(self.packed)
        with patch("core.workflow.shutil.which", return_value=None), \
             patch("core.workflow.StringExtractor.extract_from_bytes", side_effect=AssertionError("strings extracted")):
            report = analyze_file(path)
        self.assertEqual(report["unpacking"]["status"], "unavailable")
        self.assertIsNone(report["strings"])
        self.assertIsNone(report["apis"])
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("provide an unpacked file", report["unpacking"]["message"])
        output = io.StringIO()
        with patch("cli.visualizer.console", Console(file=output, width=160)):
            render_report(report)
        self.assertIn("provide an unpacked file", output.getvalue())
        self.assertIn("Collection incomplete", output.getvalue())

    def test_dot_upx_section_is_detected(self):
        contents = self.packed.replace(b"UPX0", b".upx").replace(b"UPX1", b".foo")
        path = self.write_sample(contents)
        with patch("core.workflow.shutil.which", return_value=None):
            report = analyze_file(path)
        self.assertTrue(report["pe_metadata"]["packing"]["is_packed"])
        self.assertEqual(report["unpacking"]["status"], "unavailable")

    def test_unknown_packer_skips_upx_and_strings(self):
        path = self.write_sample(self.packed.replace(b"UPX0", b".vmp0").replace(b"UPX1", b".vmp1"))
        with patch("core.workflow.subprocess.run", side_effect=AssertionError("UPX called")), \
             patch("core.workflow.StringExtractor.extract_from_bytes", side_effect=AssertionError("strings extracted")):
            report = analyze_file(path)
        self.assertEqual(report["unpacking"]["status"], "unsupported")
        self.assertEqual(report["pe_metadata"]["packing"]["packer"]["name"], "VMProtect")
        self.assertIn("VMProtect", report["unpacking"]["message"])
        self.assertIsNone(report["strings"])

    def test_ambiguous_packers_do_not_run_upx(self):
        path = self.write_sample(self.packed.replace(b"UPX1", b".vmp1"))
        with patch("core.workflow.subprocess.run", side_effect=AssertionError("UPX called")):
            report = analyze_file(path)
        self.assertEqual(report["pe_metadata"]["packing"]["packer"]["status"], "ambiguous")
        self.assertEqual(report["unpacking"]["status"], "unsupported")
        self.assertIsNone(report["strings"])

    def test_aspack_and_mpress_signatures_gate_collection(self):
        for section in (b".aspack", b".MPRESS1", b".MPRESS2"):
            with self.subTest(section=section):
                contents = bytearray(self.unpacked)
                section_table = 0x80 + 4 + 20 + 0xe0
                contents[section_table:section_table + 8] = section.ljust(8, b"\0")
                path = self.write_sample(contents)
                with patch("core.workflow.subprocess.run", side_effect=AssertionError("UPX called")), \
                     patch("core.workflow.StringExtractor.extract_from_bytes", side_effect=AssertionError("strings extracted")):
                    report = analyze_file(path)
                expected = "ASPack" if section == b".aspack" else "MPRESS"
                packing = report["pe_metadata"]["packing"]
                self.assertEqual(packing["packer"]["name"], expected)
                self.assertTrue(packing["is_packed"])
                self.assertEqual(packing["weighted_score"]["score"], 0.4)
                self.assertFalse(packing["weighted_score"]["above_threshold"])
                self.assertEqual(report["unpacking"]["status"], "unsupported")
                self.assertIn(expected, report["unpacking"]["message"])
                self.assertIsNone(report["strings"])
                self.assertIsNone(report["apis"])

    def test_packing_model_is_reported_without_changing_collection(self):
        report = analyze_file(self.write_sample(self.unpacked))
        self.assertEqual(report["pe_metadata"]["packing"]["model"]["status"], "trained")
        self.assertEqual(report["status"], "complete")
        self.assertTrue(all("model_score" in item for item in report["strings"]))

    def test_upx_success_analyzes_output_without_changing_original(self):
        path = self.write_sample(self.packed)

        def fake_upx(command, **kwargs):
            self.assertEqual(command[1:3], ["-d", "-o"])
            self.assertNotEqual(command[-1], path)
            self.assertEqual(Path(command[-1]).read_bytes(), self.packed)
            Path(command[3]).write_bytes(self.unpacked)
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("core.workflow.shutil.which", return_value="/usr/bin/upx"), \
             patch("core.workflow.subprocess.run", side_effect=fake_upx):
            report = analyze_file(path)
        self.assertEqual(self.path.read_bytes(), self.packed)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["unpacking"]["status"], "success")
        self.assertEqual(report["analyzed_file"]["source"], "unpacked")
        self.assertNotEqual(report["analyzed_file"]["hashes"], report["pe_metadata"]["hashes"])

    def test_upx_failures_skip_strings(self):
        path = self.write_sample(self.packed)
        outcomes = [
            subprocess.CompletedProcess([], 1, "", "not packed by UPX"),
            subprocess.TimeoutExpired("upx", 60),
            OSError("permission denied"),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        for outcome in outcomes:
            with self.subTest(outcome=outcome), \
                 patch("core.workflow.shutil.which", return_value="/usr/bin/upx"), \
                 patch("core.workflow.subprocess.run", side_effect=outcome if isinstance(outcome, Exception) else None,
                       return_value=outcome), \
                 patch("core.workflow.StringExtractor.extract_from_bytes", side_effect=AssertionError("strings extracted")):
                report = analyze_file(path)
                self.assertEqual(report["unpacking"]["status"], "failed")
                self.assertIsNone(report["strings"])

    def test_upx_invalid_or_still_packed_output_is_rejected(self):
        path = self.write_sample(self.packed)
        for contents in (b"not a PE", self.packed):
            def fake_upx(command, **kwargs):
                Path(command[3]).write_bytes(contents)
                return subprocess.CompletedProcess(command, 0, "", "")

            with self.subTest(contents=contents[:16]), \
                 patch("core.workflow.shutil.which", return_value="/usr/bin/upx"), \
                 patch("core.workflow.subprocess.run", side_effect=fake_upx), \
                 patch("core.workflow.StringExtractor.extract_from_bytes", side_effect=AssertionError("strings extracted")):
                report = analyze_file(path)
                self.assertEqual(report["unpacking"]["status"], "failed")
                self.assertIsNone(report["strings"])

    def test_invalid_pe_and_invalid_model_are_incomplete(self):
        path = self.write_sample(b"not a PE")
        self.assertEqual(analyze_file(path)["status"], "incomplete")
        self.write_sample(self.unpacked)
        model = Path(self.directory.name) / "weights.json"
        model.write_text('{"bias": "bad"}')
        with patch("core.workflow.MODEL_PATH", model):
            report = analyze_file(path)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("Cannot load trained model", report["errors"][0])
        self.assertIsNotNone(report["strings"])
        self.assertIsNotNone(report["apis"])

    def test_model_changes_weights_and_indicators_are_not_exclusive(self):
        class FakeModel:
            def __init__(self, value):
                self.value = value

            def predict_suspiciousness(self, text):
                return self.value, self.value >= 0.5

        def entry(value, offset):
            return {"value": value, "offset": offset, "encoding": "ASCII", "entropy": 3.0}

        strings = [
            entry("powershell.exe http://example.com/payload C:\\Temp\\file.exe", 0),
            entry("WriteProcessMemory", 1),
            entry("CreateRemoteThread", 2),
        ]
        high = StringAnalyzer(model=FakeModel(0.9)).analyze_strings(strings)
        low = StringAnalyzer(model=FakeModel(0.2)).analyze_strings(strings)
        self.assertGreater(high["total_risk_score"], low["total_risk_score"])
        self.assertIn("example.com", high["iocs"]["domains"])
        self.assertTrue(high["iocs"]["paths"])
        self.assertTrue(high["iocs"]["commands"])
        self.assertIn("WriteProcessMemory", high["iocs"]["sensitive_apis"])
        self.assertEqual(high["correlation_score"], 45)
        self.assertEqual(high["top_suspicious_strings"][0]["weight"],
                         round(high["top_suspicious_strings"][0]["heuristic_weight"] * 0.9, 2))
        duplicated = StringAnalyzer(model=FakeModel(0.9)).analyze_strings(strings + [entry(strings[0]["value"], 3)])
        self.assertEqual(high["total_risk_score"], duplicated["total_risk_score"])

    def test_model_rejects_malformed_weights(self):
        weights = Path(self.directory.name) / "invalid.json"
        weights.write_text('{"bias": NaN}')
        with self.assertRaises(ValueError):
            StringClassifierModel(model_file=str(weights))

    def test_sensitive_api_features(self):
        for api in ("RtlCreateUserThread", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"):
            with self.subTest(api=api):
                self.assertEqual(StringFeatureExtractor.extract_features(api)["is_sensitive_api"], 1.0)

    def test_json_incomplete_and_input_not_overwritten(self):
        path = self.write_sample(self.packed)
        output = str(Path(self.directory.name) / "report.json")
        with patch("core.workflow.shutil.which", return_value=None), patch("main.render_report"):
            report = analyze_target(path, export_json=output)
        self.assertEqual(json.loads(Path(output).read_text()), report)
        self.assertIsNone(report["strings"])
        with self.assertRaises(ValueError):
            analyze_target(path, export_json=path)
        self.assertEqual(self.path.read_bytes(), self.packed)

    def test_cli_json_success_and_incomplete_exit_codes(self):
        project = Path(__file__).resolve().parent.parent
        output = Path(self.directory.name) / "cli-report.json"
        for index, (contents, expected_code, status) in enumerate((
            (self.unpacked, 0, "complete"),
            (b"not a PE", 2, "incomplete"),
        )):
            output = Path(self.directory.name) / f"cli-report-{index}.json"
            self.path.write_bytes(contents)
            result = subprocess.run(
                [sys.executable, str(project / "main.py"), str(self.path), "--json", str(output), "--collect-only"],
                capture_output=True, text=True, cwd=project,
            )
            self.assertEqual(result.returncode, expected_code, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report["status"], status)
            self.assertEqual(report["strings"] is None, status == "incomplete")
            if status == "incomplete":
                self.assertIn("Collection incomplete", result.stdout)
                self.assertNotIn("THRESHOLD MET", result.stdout)

    def test_real_upx_round_trip_when_available(self):
        upx = shutil.which("upx")
        spec = importlib.util.find_spec("pip")
        if not upx or spec is None or spec.origin is None:
            self.skipTest("UPX or pip's Windows PE fixture is not installed")
        fixture = Path(spec.origin).parent / "_vendor" / "distlib" / "t32.exe"
        if not fixture.is_file():
            self.skipTest("pip's Windows PE fixture is unavailable")
        packed = Path(self.directory.name) / "real-upx.exe"
        result = subprocess.run([upx, "-o", str(packed), str(fixture)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        packed_bytes = packed.read_bytes()
        report = analyze_file(str(packed))
        self.assertEqual(report["status"], "complete", report["unpacking"])
        self.assertEqual(report["unpacking"]["status"], "success")
        self.assertEqual(report["pe_metadata"]["packing"]["model"]["prediction"]["label"], "UPX")
        self.assertEqual(report["analyzed_file"]["source"], "unpacked")
        self.assertFalse(report["analyzed_file"]["packing"]["is_packed"])
        self.assertGreater(len(report["strings"]), 0)
        self.assertEqual(packed.read_bytes(), packed_bytes)


if __name__ == "__main__":
    unittest.main()
