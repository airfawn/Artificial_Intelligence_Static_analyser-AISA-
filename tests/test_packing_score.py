import json
import unittest
from pathlib import Path
from unittest.mock import patch

from core.packing_score import THRESHOLD, assess_packing_score
from core.workflow import analyze_file
from training.evaluate_packing_score import evaluate


def section(name=".text", size=False, entropy=False):
    return {"name": name, "is_discrepancy_suspicious": size, "is_high_entropy": entropy}


class TestPackingScore(unittest.TestCase):
    def test_scoring_indicators(self):
        examples = [
            ([section()], 0.0, False),
            ([section(".aspack")], 0.4, False),
            ([section(size=True)], 0.35, False),
            ([section(entropy=True)], 0.25, False),
            ([section(size=True, entropy=True)], 0.6, False),
            ([section(".MPRESS1", entropy=True)], 0.65, True),
            ([section("UPX0", size=True, entropy=True)], 1.0, True),
            ([section(".data", size=True)], 0.0, False),
        ]
        for sections, expected, above in examples:
            with self.subTest(sections=sections):
                result = assess_packing_score(sections)
                self.assertEqual(result["score"], expected)
                self.assertEqual(result["threshold"], THRESHOLD)
                self.assertEqual(result["above_threshold"], above)
        self.assertIsNone(assess_packing_score([])["score"])

    def test_exact_section_names_and_conflicting_matches(self):
        self.assertEqual(assess_packing_score([section(".upxextra")])["score"], 0.0)
        result = assess_packing_score([section("UPX0"), section(".mpress1")])
        self.assertEqual({match["name"] for match in result["matched_packers"]}, {"UPX", "MPRESS"})
        self.assertEqual(result["score"], 0.4)

    def test_scored_dataset_reproduces_evaluation(self):
        root = Path(__file__).resolve().parent.parent
        dataset = json.loads((root / "data/packing_score_dataset.json").read_text())
        reference = json.loads((root / "data/packing_public.json").read_text())
        metrics = json.loads((root / "data/packing_score_metrics.json").read_text())
        self.assertEqual(evaluate(dataset, reference), metrics)
        test = next(row for row in dataset["samples"] if row["split"] == "test")
        test["weighted_score"]["score"] = 0.6
        test["weighted_score"]["above_threshold"] = False
        with self.assertRaisesRegex(ValueError, "does not match"):
            evaluate(dataset, reference)

    def test_weighted_score_does_not_change_gate(self):
        root = Path(__file__).resolve().parent.parent
        fake_score = {"status": "experimental", "score": 1.0, "threshold": 0.6,
                      "above_threshold": True, "message": "test"}
        with patch("core.pe_analyzer.assess_packing_score", return_value=fake_score):
            report = analyze_file(str(root / "samples/sample_unpacked.exe"))
        self.assertFalse(report["pe_metadata"]["packing"]["is_packed"])
        self.assertEqual(report["unpacking"]["status"], "not_needed")
        self.assertEqual(report["pe_metadata"]["packing"]["weighted_score"]["score"], 1.0)
        self.assertEqual(report["status"], "complete")


if __name__ == "__main__":
    unittest.main()
