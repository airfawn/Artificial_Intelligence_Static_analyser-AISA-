import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from training.review_queue import build_queue
from training.teacher_packet import build_cases, write_packet


class TestTeacherPacket(unittest.TestCase):
    def test_packet_only_contains_static_model_evidence_and_private_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {
                "target": {"file": {"sha256": "a" * 64, "strings": ["profile data"],
                                    "pe": {"imports": {"sock": {"dll": "ws2.dll",
                                                                  "imports": [{"name": "connect"}]}}}}},
                "behavior": {"processes": ["dynamic-secret"]},
            }
            raw = json.dumps(report).encode()
            (root / "report.json").write_bytes(raw)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"records": [{
                "file": "report.json", "sha256": hashlib.sha256(raw).hexdigest(),
                "dataset_partition": "malware",
            }]}))
            queue = build_queue(manifest)
            queue_file = root / "queue.json"
            queue_file.write_text(json.dumps(queue))
            output = root / "packet"
            count, batches = write_packet(queue_file, output)
            self.assertEqual((count, batches), (1, ["batch-01.json"]))
            contents = (output / batches[0]).read_text()
            self.assertNotIn("malware", contents)
            self.assertNotIn("dynamic-secret", contents)
            self.assertNotIn(str(root), contents)
            self.assertNotIn("a" * 64, contents)
            case = json.loads(contents)["cases"][0]
            self.assertEqual(case["case_id"], "case-001")
            self.assertIn("connect", contents)
            self.assertEqual(json.loads((output / "local-case-mapping.json").read_text())["cases"][0]["report"],
                             str((root / "report.json").resolve()))
            with self.assertRaises(FileExistsError):
                write_packet(queue_file, output)

            queue["items"][0]["model_prompt"] += "tamper"
            with self.assertRaisesRegex(ValueError, "differs"):
                build_cases(queue)
            (root / "report.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "changed"):
                build_cases(json.loads(queue_file.read_text()))

    def test_no_pending_items_fails(self):
        with self.assertRaisesRegex(ValueError, "No pending"):
            build_cases({"version": 1, "items": [{"status": "blocked"}]})


if __name__ == "__main__":
    unittest.main()
