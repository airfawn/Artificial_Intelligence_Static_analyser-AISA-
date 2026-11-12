import copy
import json
import tempfile
import unittest
from pathlib import Path

from training.prepare_reviewed import main, prepare
from training.cape_adapter import static_evidence


def report(digest):
    return {
        "status": "complete",
        "pe_metadata": {"hashes": {"sha256": digest}},
        "strings": [{"value": "profile data", "offset": 4, "encoding": "ASCII"}],
        "categorized_strings": {"domains": [], "urls": [], "file_paths": [], "commands": []},
        "apis": {"imports": [], "delay_imports": [], "exports": []},
    }


class TestReviewedPreparation(unittest.TestCase):
    def test_cape_static_evidence_ignores_dynamic_data(self):
        cape = {
            "target": {"file": {"sha256": "c" * 64, "strings": ["profile data"],
                                "pe": {"imports": {"sock": {
                                    "dll": "ws2.dll", "imports": [{"name": "connect"}],
                                }}}}},
            "behavior": {"processes": ["this must not appear"]},
        }
        digest, evidence = static_evidence(cape)
        self.assertEqual(digest, "c" * 64)
        self.assertEqual([x["id"] for x in evidence], ["s0", "imports0"])
        self.assertIsNone(evidence[0]["offset"])
        self.assertNotIn("this must not appear", json.dumps(evidence))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cape.json").write_text(json.dumps(cape), encoding="utf-8")
            row = {
                "report_kind": "cape", "report": "cape.json", "split": "train",
                "reviewer": "analyst",
                "chosen": {"hypotheses": [], "summary": "Insufficient evidence."},
            }
            supervised, _ = prepare([row], root)
            self.assertIn("connect", supervised["train"][0]["messages"][1]["content"])
            self.assertNotIn("this must not appear", supervised["train"][0]["messages"][1]["content"])

    def test_prepares_collector_evidence_and_preference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "r.json").write_text(json.dumps(report("a" * 64)), encoding="utf-8")
            row = {
                "report": "r.json", "split": "train", "reviewer": "analyst",
                "chosen": {"hypotheses": [{
                    "possibility": "profile data", "support": "low",
                    "explanation": "A profile string is present.", "evidence_ids": ["s0"],
                    "limitations": "File access is not established.",
                }], "summary": "Static evidence."},
                "rejected": "The sample definitely read the profile.",
                "preference_reason": "An extracted string does not prove execution.",
            }
            supervised, preferences = prepare([row], root)
            self.assertIn('"id": "s0"', supervised["train"][0]["messages"][1]["content"])
            self.assertEqual(preferences["train"][0]["rejected"], row["rejected"])
            bad = copy.deepcopy(row)
            bad["chosen"]["hypotheses"][0]["evidence_ids"] = ["s999"]
            with self.assertRaisesRegex(RuntimeError, "unknown evidence"):
                prepare([bad], root)
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                prepare([row, row], root)

    def test_empty_split_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "r.json").write_text(json.dumps(report("b" * 64)), encoding="utf-8")
            source = root / "reviews.json"
            source.write_text(json.dumps([{
                "report": "r.json", "split": "train", "reviewer": "analyst",
                "chosen": {"hypotheses": [], "summary": "Insufficient evidence."},
            }]), encoding="utf-8")
            output = root / "output"
            self.assertEqual(main([str(source), "--output", str(output)]), 1)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
