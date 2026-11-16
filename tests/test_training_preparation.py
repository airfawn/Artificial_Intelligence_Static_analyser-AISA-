import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from training.legacy.prepare_reviewed import main, prepare
from training.legacy.cape_adapter import static_evidence
from training.legacy.weak_supervision import generate, split_for_evidence
from training import download_pilot


def report(digest):
    return {
        "status": "complete",
        "pe_metadata": {"hashes": {"sha256": digest}},
        "strings": [{"value": "profile data", "offset": 4, "encoding": "ASCII"}],
        "categorized_strings": {"domains": [], "urls": [], "file_paths": [], "commands": []},
        "apis": {"imports": [], "delay_imports": [], "exports": []},
    }


@patch("training.legacy.prepare_reviewed.block_untrusted_llm", lambda: None)
@patch("training.legacy.legacy_behavior_analysis.block_untrusted_llm", lambda: None)
class TestReviewedPreparation(unittest.TestCase):
    def test_expanded_report_sources_keep_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reports"

            def download(entry, local):
                return {"file": f"{local.name}/{entry['name']}"}

            args = ["download_pilot", "--output", str(output), "--per-class", "2",
                    "--source", "malware", "--source", "portableapps"]
            with patch("sys.argv", args), \
                 patch.object(download_pilot, "catalog", return_value=[{"name": "report.json"}]), \
                 patch.object(download_pilot, "download", side_effect=download):
                download_pilot.main()
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(
                [(row["source_group"], row["dataset_partition"], row["file"])
                 for row in manifest["records"]],
                [("malware", "malware", "malware/report.json"),
                 ("portableapps", "benign", "portableapps/report.json")],
            )

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


@patch("training.legacy.weak_supervision.block_untrusted_llm", lambda: None)
@patch("training.legacy.legacy_behavior_analysis.block_untrusted_llm", lambda: None)
class TestWeakSupervision(unittest.TestCase):
    def test_static_only_student_prompts_and_grouped_splits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = []
            found = set()
            number = 0
            while len(found) < 3:
                cape = {
                    "target": {"file": {
                        "sha256": f"{number:064x}",
                        "strings": [f"static value {number}"],
                        "pe": {"imports": {"sock": {
                            "dll": "ws2.dll", "imports": [{"name": "connect"}],
                        }}},
                    }},
                    "signatures": [{"name": "private_dynamic_hint", "description": "sandbox observation"}],
                }
                _, evidence = static_evidence(cape)
                split = split_for_evidence(evidence)
                if split in found:
                    number += 1
                    continue
                found.add(split)
                payload = json.dumps(cape).encode()
                path = root / f"{number}.json"
                path.write_bytes(payload)
                records.append({
                    "file": path.name, "sha256": hashlib.sha256(payload).hexdigest(),
                    "dataset_partition": "malware" if len(records) < 2 else "benign",
                })
                number += 1
            records[0]["dataset_partition"] = "benign"
            records[1]["dataset_partition"] = "malware"
            records[2]["dataset_partition"] = "malware"
            manifest = root / "manifest.json"
            output = root / "output"
            other = json.loads((root / records[0]["file"]).read_text())
            other["target"]["file"]["sha256"] = "f" * 64
            other["target"]["file"]["strings"].append("another benign value")
            payload = json.dumps(other).encode()
            (root / "extra.json").write_bytes(payload)
            records.insert(1, {
                "file": "extra.json", "sha256": hashlib.sha256(payload).hexdigest(),
                "dataset_partition": "benign",
            })
            manifest.write_text(json.dumps({"records": records}), encoding="utf-8")
            answer = {"hypotheses": [], "summary": "Insufficient static evidence."}
            with patch("training.legacy.weak_supervision.query_model", return_value=answer) as query:
                generate(manifest, output, 2, "local-model", 11434)
            self.assertTrue(all("private_dynamic_hint" in call.args[0] for call in query.call_args_list))
            for name in ("train", "valid", "test"):
                for line in (output / f"{name}.jsonl").read_text().splitlines():
                    student = json.loads(line)["messages"][1]["content"]
                    self.assertNotIn("private_dynamic_hint", student)
                    self.assertNotIn("source_partition", student)
            metadata = json.loads((output / "provenance.json").read_text())
            self.assertIn("not reviewed", metadata["warning"])
            invalid = {"hypotheses": [{
                "possibility": "network access", "support": "low",
                "explanation": "A networking import is present.",
                "evidence_ids": ["imports999"], "limitations": "Execution is unknown.",
            }], "summary": "Static evidence."}
            failed = root / "failed"
            with patch("training.legacy.weak_supervision.query_model", return_value=invalid):
                with self.assertRaisesRegex(RuntimeError, "unknown evidence"):
                    generate(manifest, failed, 2, "local-model", 11434)
            self.assertFalse((failed / "provenance.json").exists())
            interrupted = root / "interrupted"
            with patch("training.legacy.weak_supervision.query_model",
                       side_effect=[answer, RuntimeError("interrupted")]):
                with self.assertRaisesRegex(RuntimeError, "interrupted"):
                    generate(manifest, interrupted, 2, "local-model", 11434)
            with patch("training.legacy.weak_supervision.query_model", return_value=answer) as resumed:
                generate(manifest, interrupted, 2, "local-model", 11434, resume=True)
            self.assertEqual(resumed.call_count, 3)
            self.assertEqual(len(json.loads((interrupted / "provenance.json").read_text())["records"]), 4)


@patch("training.legacy.evaluate_weak.block_untrusted_llm", lambda: None)
class TestWeakEvaluation(unittest.TestCase):
    def write_data(self, root):
        (root / "provenance.json").write_text(json.dumps({
            "records": [{"split": "test", "sha256": "a" * 64, "partition": "malware"}],
        }))
        answer = {"hypotheses": [{
            "possibility": "network access", "support": "low",
            "explanation": "A networking import is present.",
            "evidence_ids": ["imports0"], "limitations": "Execution is unknown.",
        }], "summary": "Static evidence."}
        messages = [
            {"role": "system", "content": "test"},
            {"role": "user", "content": 'Evidence:\n[{"id":"imports0","value":"connect"}]'},
            {"role": "assistant", "content": json.dumps(answer)},
        ]
        (root / "test.jsonl").write_text(json.dumps({"messages": messages}) + "\n")
        return answer

    @unittest.skipUnless(importlib.util.find_spec("mlx_lm"), "MLX-LM is not installed")
    def test_evaluation_counts_reference_overlap_and_rejects_bad_citations(self):
        from training.legacy.evaluate_weak import evaluate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            answer = self.write_data(root)
            with patch("mlx_lm.load", return_value=(object(), unittest.mock.Mock())), \
                 patch("mlx_lm.generate", return_value=json.dumps(answer)):
                result = evaluate(root, root / "model", None)["results"][0]
            self.assertTrue(result["valid"])
            self.assertEqual(result["matching_reference_evidence_count"], 1)
            answer["hypotheses"][0]["evidence_ids"] = ["imports999"]
            with patch("mlx_lm.load", return_value=(object(), unittest.mock.Mock())), \
                 patch("mlx_lm.generate", return_value=json.dumps(answer)):
                result = evaluate(root, root / "model", None)["results"][0]
            self.assertFalse(result["valid"])
            self.assertIn("unknown evidence", result["error"])

    def test_ollama_evaluation_uses_local_constrained_schema(self):
        from training.legacy.evaluate_weak import evaluate_ollama

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            answer = self.write_data(root)
            with patch("training.legacy.evaluate_weak.query_model", return_value=answer) as query:
                result = evaluate_ollama(root, "local-model", 1234)["results"][0]
            self.assertTrue(result["valid"])
            self.assertEqual(query.call_args.kwargs["endpoint"], "http://127.0.0.1:1234/api/chat")
            schema = query.call_args.args[1]
            references = schema["properties"]["hypotheses"]["items"]["properties"]["evidence_ids"]
            self.assertEqual(references["items"]["enum"], ["imports0"])


if __name__ == "__main__":
    unittest.main()
