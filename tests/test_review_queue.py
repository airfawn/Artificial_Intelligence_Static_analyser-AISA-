import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from training.legacy.review_queue import approved_records, build_queue


def cape(digest, count=1):
    return {
        "target": {"file": {
            "sha256": digest,
            "strings": ["profile data"],
            "pe": {"imports": {"test": {
                "dll": "test.dll",
                "imports": [{"name": "function" + str(i)} for i in range(count)],
            }}},
        }},
        "behavior": {"processes": ["dynamic data must not become evidence"]},
    }


@patch("training.legacy.prepare_reviewed.block_untrusted_llm", lambda: None)
@patch("training.legacy.legacy_behavior_analysis.block_untrusted_llm", lambda: None)
@patch("training.legacy.review_queue.block_untrusted_llm", lambda: None)
class TestReviewQueue(unittest.TestCase):
    def test_queue_and_review_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            items = []
            for name, value in (("a", cape("a" * 64)), ("duplicate", cape("a" * 64)),
                                ("large", cape("b" * 64, 500))):
                payload = json.dumps(value).encode()
                (root / f"{name}.json").write_bytes(payload)
                items.append({"file": f"{name}.json", "sha256": hashlib.sha256(payload).hexdigest(),
                              "dataset_partition": "malware"})
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"records": items}), encoding="utf-8")
            queue = build_queue(manifest)
            self.assertEqual([x["status"] for x in queue["items"]], ["pending", "blocked", "blocked"])
            self.assertNotIn("dynamic data must not become evidence", queue["items"][0]["model_prompt"])
            with self.assertRaisesRegex(ValueError, "No reviewed"):
                approved_records(queue)
            item = queue["items"][0]
            item.update({
                "status": "reviewed", "split": "train", "reviewer": "analyst",
                "chosen": {"hypotheses": [], "summary": "Insufficient evidence."},
            })
            approved, counts = approved_records(queue)
            self.assertEqual(len(approved), 1)
            self.assertEqual(counts["blocked"], 2)
            item["chosen"] = {"hypotheses": [{
                "possibility": "test", "support": "low", "explanation": "test",
                "evidence_ids": ["unknown"], "limitations": "test",
            }], "summary": "test"}
            with self.assertRaisesRegex(RuntimeError, "unknown evidence"):
                approved_records(queue)
            (root / "a.json").write_text("modified", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed"):
                approved_records(queue)

    def test_manifest_integrity_and_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"records": [
                {"file": "../outside.json", "sha256": "a" * 64}
            ]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid report path"):
                build_queue(manifest)
            (root / "report.json").write_text("{}", encoding="utf-8")
            manifest.write_text(json.dumps({"records": [
                {"file": "report.json", "sha256": "a" * 64}
            ]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum"):
                build_queue(manifest)

    def test_incomplete_static_reports_are_blocked_not_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = []
            incomplete = cape("a" * 64)
            del incomplete["target"]["file"]["pe"]
            for name, value in (("incomplete", incomplete), ("complete", cape("b" * 64))):
                payload = json.dumps(value).encode()
                (root / f"{name}.json").write_bytes(payload)
                records.append({"file": f"{name}.json", "sha256": hashlib.sha256(payload).hexdigest()})
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"records": records}))
            items = build_queue(manifest)["items"]
            self.assertEqual([item["status"] for item in items], ["blocked", "pending"])
            self.assertIn("Static evidence unavailable", items[0]["blocked_reason"])


if __name__ == "__main__":
    unittest.main()
