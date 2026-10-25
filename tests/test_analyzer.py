"""
Unit tests for the Static Analysis Engine:
- PE Header & Packing Heuristics
- Dual-encoding string extractor (ASCII & UTF-16LE)
- Weighted string scoring and IOC categorization
- ML feature extraction & RL feedback trainer
"""

import unittest
from core.pe_analyzer import calculate_hashes, calculate_entropy, PEAnalyzer
from core.string_extractor import StringExtractor, calculate_string_entropy
from core.string_analyzer import StringAnalyzer
from core.ml_model import StringFeatureExtractor, StringClassifierModel, RLFeedbackTrainer
from samples.create_sample import build_minimal_pe


class TestStaticAnalysisEngine(unittest.TestCase):

    def setUp(self):
        self.unpacked_pe = build_minimal_pe(packed=False)
        self.packed_pe = build_minimal_pe(packed=True)
        self.extractor = StringExtractor(min_length=4)
        self.analyzer = StringAnalyzer()

    def test_hashes_and_entropy(self):
        hashes = calculate_hashes(self.unpacked_pe)
        self.assertIn("md5", hashes)
        self.assertIn("sha256", hashes)
        self.assertEqual(len(hashes["sha256"]), 64)

        entropy = calculate_entropy(b"\x00" * 100)
        self.assertEqual(entropy, 0.0)

    def test_native_string_extractor_dual_encoding(self):
        strings = self.extractor.extract_from_bytes(self.unpacked_pe)
        extracted_values = [s["value"] for s in strings]
        encodings = {s["value"]: s["encoding"] for s in strings}

        # ASCII checks
        self.assertIn("VirtualAllocEx", extracted_values)
        self.assertEqual(encodings["VirtualAllocEx"], "ASCII")

        # UTF-16LE checks
        self.assertIn("MiniDumpWriteDump", extracted_values)
        self.assertEqual(encodings["MiniDumpWriteDump"], "UTF-16LE")

    def test_weighted_string_rules(self):
        # 1. Links: Instant Suspicious (weight >= 35)
        w, reasons, cat = self.analyzer.evaluate_string({
            "value": "http://malicious-c2.com/payload.exe",
            "entropy": 3.5,
        })
        self.assertGreaterEqual(w, 35)
        self.assertEqual(cat, "Network / C2 Link")

        # 2. Paths: High Suspicious
        w_path, _, cat_path = self.analyzer.evaluate_string({
            "value": "C:\\Windows\\System32\\cmd.exe",
            "entropy": 3.0,
        })
        self.assertGreaterEqual(w_path, 25)

        # 3. Injection APIs: Critical
        w_inj, _, cat_inj = self.analyzer.evaluate_string({
            "value": "WriteProcessMemory",
            "entropy": 3.0,
        })
        self.assertGreaterEqual(w_inj, 35)
        self.assertEqual(cat_inj, "Process Injection API")

    def test_ml_features_and_rl_feedback(self):
        # Feature extraction
        feats = StringFeatureExtractor.extract_features("http://192.168.1.1:8080/beacon")
        self.assertEqual(feats["has_url_prefix"], 1.0)

        # RL trainer feedback step
        model = StringClassifierModel(model_file="models/test_weights.json")
        trainer = RLFeedbackTrainer(model=model, learning_rate=0.1)

        # Ground truth: Obfuscated string (True Positive reward)
        step_log = trainer.feedback_step("aHR0cHM6Ly9ldmlsLmNvbS9jMi5iYXR=", ground_truth_suspicious=True)
        self.assertIn("reward", step_log)
        self.assertIn("prob_before", step_log)


if __name__ == "__main__":
    unittest.main()
