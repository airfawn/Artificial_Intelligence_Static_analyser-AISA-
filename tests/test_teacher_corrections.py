import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from training.legacy.prepare_teacher_corrections import build_corrections


@patch("training.legacy.prepare_teacher_corrections.block_untrusted_llm", lambda: None)
class TestTeacherCorrections(unittest.TestCase):
    def test_selects_invalid_citations_and_rejects_missing_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory)
            (packet / "batch-01.json").write_text(json.dumps({"cases": [
                {"case_id": "case-001", "evidence": [{"id": "s0", "value": "test"}]},
                {"case_id": "case-002", "evidence": [{"id": "s1", "value": "test"}]},
            ]}), encoding="utf-8")
            analysis = {
                "hypotheses": [{"possibility": "test", "support": "low", "explanation": "test",
                                "evidence_ids": ["unknown"], "limitations": "test"}],
                "summary": "test",
            }
            response = {"cases": [
                {"case_id": "case-001", "analysis": analysis},
                {"case_id": "case-002", "analysis": {"hypotheses": [], "summary": "insufficient"}},
            ]}
            corrections = build_corrections(packet, response)
            self.assertEqual([x["case_id"] for x in corrections["cases"]], ["case-001"])
            self.assertEqual(corrections["cases"][0]["evidence"][0]["id"], "s0")
            with self.assertRaisesRegex(ValueError, "Missing cases"):
                build_corrections(packet, {"cases": response["cases"][:1]})


if __name__ == "__main__":
    unittest.main()
