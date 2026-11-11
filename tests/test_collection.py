import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.console import Console
from cli.visualizer import render_report
from core.string_extractor import StringExtractor
from core.workflow import analyze_file
from main import analyze_target
from samples.create_sample import build_minimal_pe


def build_api_fixture():
    """Create a PE32 fixture with named and ordinal imports, delay imports, and exports."""
    data = bytearray(build_minimal_pe(packed=False))
    data.extend(b"\0" * max(0, 0x1800 - len(data)))
    base = 0x800
    rva = 0x2000
    directories = 0x80 + 4 + 20 + 96

    def directory(index, offset, size):
        struct.pack_into("<II", data, directories + index * 8, rva + offset, size)

    def put(offset, value):
        data[base + offset:base + offset + len(value)] = value

    directory(1, 0x100, 40)
    put(0x100, struct.pack("<IIIII", rva + 0x180, 0, 0, rva + 0x170, rva + 0x180))
    put(0x170, b"KERNEL32.dll\0")
    put(0x180, struct.pack("<III", rva + 0x1a0, 0x80000007, 0))
    put(0x1a0, b"\x05\x00CreateFileW\0")

    directory(13, 0x200, 64)
    put(0x200, struct.pack("<IIIIIIII", 1, rva + 0x270, 0, rva + 0x280, rva + 0x280, 0, 0, 0))
    put(0x270, b"USER32.dll\0")
    put(0x280, struct.pack("<III", rva + 0x2a0, 0x80000009, 0))
    put(0x2a0, b"\x03\x00MessageBoxW\0")

    directory(0, 0x300, 0x100)
    put(0x300, struct.pack(
        "<IIHHIIIIIII", 0, 0, 0, 0, rva + 0x370, 1, 2, 1,
        rva + 0x380, rva + 0x390, rva + 0x3a0,
    ))
    put(0x370, b"sample.dll\0")
    put(0x380, struct.pack("<II", 0x1000, rva + 0x3d0))
    put(0x390, struct.pack("<I", rva + 0x3b0))
    put(0x3a0, struct.pack("<H", 0))
    put(0x3b0, b"ExportedFunction\0")
    put(0x3d0, b"OTHER.Forwarded\0")
    return bytes(data)


class TestModuleOneCollection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "sample.exe"

    def test_imports_delay_imports_exports_and_hashes(self):
        data = build_api_fixture()
        self.path.write_bytes(data)
        report = analyze_file(str(self.path))
        self.assertEqual(report["status"], "complete", report["errors"])
        apis = report["apis"]
        self.assertEqual([(i["dll"], i["name"], i["ordinal"]) for i in apis["imports"]],
                         [("KERNEL32.dll", "CreateFileW", None), ("KERNEL32.dll", None, 7)])
        self.assertEqual([(i["dll"], i["name"], i["ordinal"]) for i in apis["delay_imports"]],
                         [("USER32.dll", "MessageBoxW", None), ("USER32.dll", None, 9)])
        self.assertEqual(apis["export_dll"], "sample.dll")
        self.assertEqual([(i["name"], i["ordinal"], i["forwarder"]) for i in apis["exports"]],
                         [("ExportedFunction", 1, None), (None, 2, "OTHER.Forwarded")])
        self.assertEqual(report["pe_metadata"]["hashes"]["md5"], hashlib.md5(data).hexdigest())
        self.assertEqual(report["pe_metadata"]["hashes"]["sha256"], hashlib.sha256(data).hexdigest())

    def test_all_strings_including_duplicates_and_noise_are_retained(self):
        data = bytes(build_minimal_pe(packed=False)) + b"\0bad allocation\0bad allocation\0"
        self.path.write_bytes(data)
        expected = StringExtractor().extract_from_bytes(data)
        report = analyze_file(str(self.path))
        actual = report["strings"]
        self.assertEqual(len(actual), len(expected))
        self.assertEqual([s["value"] for s in actual], [s["value"] for s in expected])
        self.assertEqual(sum(s["value"] == "bad allocation" for s in actual), 2)
        self.assertTrue(all("entropy" in item and "model_score" in item for item in actual))

    def test_automatic_reports_do_not_overwrite_existing_files(self):
        self.path.write_bytes(build_minimal_pe(packed=False))
        first = self.path.with_name(self.path.name + ".report.json")
        first.write_text("existing")
        with patch("main.render_report"):
            report = analyze_target(str(self.path))
            second = self.path.with_name(self.path.name + ".report.1.json")
            self.assertEqual(json.loads(second.read_text()), report)
            analyze_target(str(self.path))
        self.assertEqual(first.read_text(), "existing")
        self.assertTrue(self.path.with_name(self.path.name + ".report.2.json").exists())
        with self.assertRaises(FileExistsError):
            analyze_target(str(self.path), export_json=str(first))
        self.assertEqual(first.read_text(), "existing")

    def test_invalid_pe_still_saves_partial_report(self):
        self.path.write_bytes(b"not a PE")
        with patch("main.render_report"):
            report = analyze_target(str(self.path))
        saved = self.path.with_name(self.path.name + ".report.json")
        self.assertEqual(json.loads(saved.read_text()), report)
        self.assertEqual(report["status"], "incomplete")
        self.assertIsNone(report["strings"])
        self.assertIsNone(report["apis"])

    def test_bad_directory_is_reported_as_incomplete(self):
        data = bytearray(build_minimal_pe(packed=False))
        struct.pack_into("<II", data, 0x80 + 4 + 20 + 96 + 8, 0x7FFFFFFF, 40)
        self.path.write_bytes(data)
        report = analyze_file(str(self.path))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["apis"]["directories"]["imports"]["status"], "unreadable")
        self.assertIsNone(report["apis"]["imports"])
        self.assertTrue(report["errors"])
        self.assertIsNotNone(report["strings"])
        self.assertEqual(report["apis"]["directories"]["delay_imports"]["status"], "absent")
        self.assertEqual(report["apis"]["delay_imports"], [])

        output = io.StringIO()
        with patch("cli.visualizer.console", Console(file=output, width=160)):
            render_report(report)
        self.assertIn("Imports: unreadable", output.getvalue())
        self.assertIn("contents are unknown", output.getvalue())
        self.assertIn("Delay imports: absent", output.getvalue())
        self.assertNotIn("Imports: 0", output.getvalue())

        with patch("main.render_report"):
            saved_report = analyze_target(str(self.path))
        saved = self.path.with_name(self.path.name + ".report.json")
        self.assertEqual(json.loads(saved.read_text()), saved_report)
        self.assertIsNone(saved_report["apis"]["imports"])


if __name__ == "__main__":
    unittest.main()
