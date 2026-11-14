import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from cli.visualizer import render_ai_analysis
from core.api_analysis import analyze_report, load_model
from training.train_api_model import train


def cape(digest, names, family=""):
    file = {"sha256": digest, "cape_type": family}
    if names is not None:
        file["pe"] = {"imports": {"lib": {"imports": [{"name": name} for name in names]}}}
    return {"target": {"file": file}}


class TestAPIAnalysis(unittest.TestCase):
    def test_training_counts_samples_and_skips_missing_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = [
                ("malware", cape("a" * 64, ["ReadFile", "ReadFile", "send"], "Example Payload")),
                ("malware", cape("b" * 64, ["ReadFile"])),
                ("benign", cape("c" * 64, ["ReadFile"])),
                ("benign", cape("c" * 64, ["ReadFile"])),
                ("benign", cape("d" * 64, None)),
            ]
            records = []
            for index, (partition, data) in enumerate(rows):
                payload = json.dumps(data).encode()
                name = f"{index}.json"
                (root / name).write_bytes(payload)
                records.append({"file": name, "sha256": hashlib.sha256(payload).hexdigest(),
                                "dataset_partition": partition})
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"records": records}))
            model = train(manifest)
            self.assertEqual(model["sample_counts"], {"malware": 2, "benign": 1})
            self.assertEqual(model["duplicate_reports"], 1)
            self.assertEqual(model["skipped_missing_imports"], 1)
            self.assertEqual(model["imports"]["malware"]["readfile"], 2)
            self.assertEqual(model["patterns"]["malware"]["file_read_and_network_send"], 1)
            self.assertEqual(model["cooccurrences"]["malware"]["readfile|send"], 1)
            self.assertEqual(model["weak_families"]["Example Payload"]["imports"]["send"], 1)

            report = {"status": "complete", "apis": {
                "imports": [{"name": "ReadFile", "dll": "KERNEL32.dll"}, {"name": None}],
                "delay_imports": [{"name": "send", "dll": "WS2_32.dll"}],
            }}
            result = analyze_report(report, model)
            send = next(item for item in result["flagged_imports"] if item["name"] == "send")
            self.assertEqual(send["evidence"][0]["table"], "delay_imports")
            self.assertEqual(send["weak_family_counts"], [{"label": "Example Payload", "count": 1, "samples": 1}])
            self.assertEqual(result["patterns"][0]["malware_reports"], 1)
            self.assertEqual(result["observed_associations"], [])
            self.assertEqual({ref["name"] for ref in result["patterns"][0]["evidence"]}, {"ReadFile", "send"})
            output = io.StringIO()
            with patch("cli.visualizer.console", Console(file=output, width=160)):
                render_ai_analysis(result)
            self.assertIn("Unverified family Example Payload: 1/1", output.getvalue())
            self.assertIn("Combination", output.getvalue())

            model["sample_counts"]["malware"] = 3
            model["cooccurrences"]["malware"]["readfile|send"] = 3
            association = analyze_report(report, model)["observed_associations"][0]
            self.assertEqual(association["names"], ["readfile", "send"])
            self.assertEqual(association["malware_reports"], 3)
            report["apis"]["delay_imports"] = []
            self.assertEqual(analyze_report(report, model)["patterns"], [])
            report["apis"]["imports"] = [{"name": None}]
            self.assertEqual(analyze_report(report, model)["flagged_imports"], [])

            records[0]["sha256"] = "0" * 64
            manifest.write_text(json.dumps({"records": records}))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                train(manifest)

    def test_invalid_model_and_unavailable_imports_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            path.write_text('{"version":1,"sample_counts":[]}')
            with self.assertRaisesRegex(ValueError, "Invalid API frequency model"):
                load_model(path)
        with self.assertRaisesRegex(ValueError, "complete"):
            analyze_report({"status": "incomplete"})
        with self.assertRaisesRegex(ValueError, "delay_imports"):
            analyze_report({"status": "complete", "apis": {"imports": [], "delay_imports": None}})

    def test_duplicate_with_imports_replaces_missing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = []
            for index, (label, data) in enumerate((
                ("malware", cape("a" * 64, None)),
                ("malware", cape("a" * 64, ["ReadFile"])),
                ("benign", cape("b" * 64, ["WriteFile"])),
            )):
                payload = json.dumps(data).encode()
                name = f"{index}.json"
                (root / name).write_bytes(payload)
                records.append({"file": name, "sha256": hashlib.sha256(payload).hexdigest(),
                                "dataset_partition": label})
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"records": records}))
            model = train(manifest)
            self.assertEqual(model["duplicate_reports"], 1)
            self.assertEqual(model["skipped_missing_imports"], 0)
            self.assertEqual(model["imports"]["malware"]["readfile"], 1)


if __name__ == "__main__":
    unittest.main()
