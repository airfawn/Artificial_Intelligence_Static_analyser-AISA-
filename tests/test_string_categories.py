import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.string_categories import categorize_strings
from core.workflow import analyze_file
from main import analyze_target
from samples.create_sample import build_minimal_pe


def entry(value, offset, encoding="ASCII"):
    return {"value": value, "offset": offset, "encoding": encoding, "entropy": 3.0}


class TestStringCategories(unittest.TestCase):
    def test_multiple_indicators_and_provenance(self):
        source = 'cmd.exe /c powershell -c "https://Example.com/a?q=1" "C:\\Program Files\\app.exe"'
        strings = [entry(source, 123)]
        result = categorize_strings(strings)
        self.assertEqual([x["value"] for x in result["commands"]], [source])
        self.assertEqual([x["value"] for x in result["urls"]], ["https://Example.com/a?q=1"])
        self.assertEqual([x["value"] for x in result["domains"]], ["Example.com"])
        self.assertEqual([x["value"] for x in result["file_paths"]], ['"C:\\Program Files\\app.exe"'])
        for matches in result.values():
            for match in matches:
                self.assertEqual(match["string_index"], 0)
                self.assertEqual(match["string_offset"], 123)
                self.assertEqual(source[match["match_start"]:match["match_end"]], match["value"])

    def test_multiple_occurrences_duplicates_and_encodings(self):
        strings = [
            entry("other.net example.org example.org", 5),
            entry("example.org", 60, "UTF-16LE"),
            entry("%TEMP%\\download.exe", 100),
        ]
        result = categorize_strings(strings)
        self.assertEqual([x["value"] for x in result["domains"]],
                         ["example.org", "example.org", "example.org", "other.net"])
        self.assertEqual([x["encoding"] for x in result["domains"][:3]],
                         ["ASCII", "ASCII", "UTF-16LE"])
        self.assertEqual(result["file_paths"][0]["value"], "%TEMP%\\download.exe")

    def test_candidates_avoid_common_false_matches(self):
        strings = [
            entry("acmdtest cmdline KERNEL32.dll", 0),
            entry("http://192.168.1.1/a.exe", 40),
            entry("https://example.com/a/file.exe", 80),
            entry("cmd /c echo test", 120),
        ]
        result = categorize_strings(strings)
        self.assertEqual([x["value"] for x in result["domains"]], ["example.com"])
        self.assertEqual(result["file_paths"], [])
        self.assertEqual([x["value"] for x in result["commands"]], ["cmd /c echo test"])
        self.assertEqual(len(result["urls"]), 2)

    def test_domain_candidates_skip_filenames_and_registry_components(self):
        strings = [
            entry("%s\\32BitFtp.ini %s\\Accounts.tdat %s\\user.config", 0),
            entry("Software\\9bis.com\\KiTTY\\Sessions", 50),
            entry("Mozilla.org", 100),
            entry("Fuckav.ru", 120),
        ]
        result = categorize_strings(strings)
        self.assertEqual([item["value"] for item in result["domains"]],
                         ["Fuckav.ru", "Mozilla.org"])

    def test_workflow_and_json_persist_categories_even_without_model(self):
        payload = b'\x00cmd.exe /c https://example.org/a.exe C:\\Temp\\file.exe\x00'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.exe"
            path.write_bytes(bytes(build_minimal_pe()) + payload)
            with patch("core.workflow.MODEL_PATH", Path(directory) / "missing.json"), patch("main.render_report"):
                report = analyze_target(str(path), format="json")
            self.assertEqual(report["status"], "incomplete")
            self.assertTrue(report["categorized_strings"]["commands"])
            self.assertTrue(report["categorized_strings"]["domains"])
            self.assertTrue(report["categorized_strings"]["file_paths"])
            output = json.loads(path.with_name(path.name + ".report.json").read_text())
            self.assertEqual(output["categorized_strings"], report["categorized_strings"])
            self.assertEqual(output["strings"], report["strings"])

    def test_packed_file_has_no_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packed.exe"
            path.write_bytes(build_minimal_pe(packed=True))
            with patch("core.workflow.shutil.which", return_value=None):
                report = analyze_file(str(path))
            self.assertIsNone(report["categorized_strings"])

    def test_cli_displays_and_saves_sorted_categories(self):
        project = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.exe"
            path.write_bytes(bytes(build_minimal_pe()) + b"\x00cmd.exe /c http://example.org/a C:\\Temp\\file.exe\x00")
            result = subprocess.run(
                [sys.executable, str(project / "main.py"), str(path), "--collect-only", "--format=json"],
                capture_output=True, text=True, cwd=project,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for title in ("Domains:", "File paths:", "URLs:", "Command-line candidates:"):
                self.assertIn(title, result.stdout)
            report = json.loads(path.with_name(path.name + ".report.json").read_text())
            for key in ("domains", "file_paths", "urls", "commands"):
                self.assertTrue(report["categorized_strings"][key], key)
            self.assertTrue(any("cmd.exe /c http://example.org/a" in x["value"]
                                for x in report["categorized_strings"]["commands"]))


if __name__ == "__main__":
    unittest.main()
