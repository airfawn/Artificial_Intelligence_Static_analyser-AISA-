import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from samples.create_sample import build_minimal_pe


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
        for option in ("-f", "-s", "-h", "--min-len"):
            self.assertIn(option, result.stdout)

    def test_file_and_save_options(self):
        destination = Path(self.directory.name) / "report.json"
        result = self.run_cli("-f", self.path, "-s", destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(destination.read_text())["status"], "complete")
        self.assertIn(str(destination), result.stdout)
        result = self.run_cli("-f", self.path, "-s", destination)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(destination.read_text())["status"], "complete")

    def test_default_and_legacy_options(self):
        result = self.run_cli("-f", self.path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.path.with_name(self.path.name + ".report.json").is_file())
        legacy = Path(self.directory.name) / "legacy.json"
        result = self.run_cli(self.path, "-j", legacy)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(legacy.is_file())

    def test_invalid_cli_usage(self):
        for args in ((), ("-f",), ("-s", "report.json"), ("-f", self.path, self.path)):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)

    def test_incomplete_report_is_saved(self):
        self.path.write_bytes(b"not a PE")
        destination = Path(self.directory.name) / "partial.json"
        result = self.run_cli("-f", self.path, "-s", destination)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(destination.read_text())["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
