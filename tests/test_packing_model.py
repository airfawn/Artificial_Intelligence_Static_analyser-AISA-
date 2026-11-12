import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.packer_signatures import identify_packer
from core.packing_model import FEATURES, PackingClassifierModel, assess_packing, extract_packing_features
from training.packing_baseline import train_dataset


class TestPackingIdentification(unittest.TestCase):
    def test_known_packers_and_case_insensitivity(self):
        for section, label in (
            ("UPX0", "UPX"), (".ASPACK", "ASPack"), (".fsg", "FSG"),
            (".MPRESS1", "MPRESS"), (".mpress2", "MPRESS"),
            (".themida", "Themida"), (".vmp1", "VMProtect"), ("PEC2", "PECompact"),
            (".nsp0", "NsPack"), ("MEW", "MEW"), (".enigma", "Enigma"),
        ):
            with self.subTest(section=section):
                result = identify_packer([{"name": section}])
                self.assertEqual(result["status"], "identified")
                self.assertEqual(result["name"], label)

    def test_unknown_and_conflicting_signatures(self):
        self.assertEqual(identify_packer([{"name": ".adata"}])["status"], "unknown")
        result = identify_packer([{"name": "UPX0"}, {"name": ".vmp0"}])
        self.assertEqual(result["status"], "ambiguous")
        self.assertIsNone(result["name"])
        self.assertEqual({match["name"] for match in result["matches"]}, {"UPX", "VMProtect"})


class TestPackingModel(unittest.TestCase):
    def test_untrained_model_does_not_predict(self):
        model = PackingClassifierModel()
        features = extract_packing_features({"sections": []})
        self.assertEqual(features, dict.fromkeys(FEATURES, 0.0))
        with self.assertRaisesRegex(ValueError, "untrained"):
            model.predict(features)

    def test_fit_and_predict(self):
        clean = dict.fromkeys(FEATURES, 0.0)
        packed = dict.fromkeys(FEATURES, 1.0)
        model = PackingClassifierModel()
        model.fit([(clean, "unpacked"), (packed, "UPX")])
        self.assertEqual(model.predict(clean), {"label": "unpacked", "distance": 0.0})
        self.assertEqual(model.predict(packed), {"label": "UPX", "distance": 0.0})
        assessment = model.assess({"sections": []})
        self.assertEqual(assessment["status"], "trained")
        self.assertEqual(assessment["prediction"]["label"], "unpacked")

    def test_rejects_bad_training_or_prediction_inputs(self):
        model = PackingClassifierModel()
        clean = dict.fromkeys(FEATURES, 0.0)
        with self.assertRaisesRegex(ValueError, "two distinct"):
            model.fit([(clean, "UPX")])
        with self.assertRaisesRegex(ValueError, "features"):
            model.fit([({}, "UPX"), (clean, "unpacked")])
        model.fit([(clean, "unpacked"), (dict.fromkeys(FEATURES, 1.0), "UPX")])
        invalid = dict(clean, max_entropy=float("nan"))
        with self.assertRaisesRegex(ValueError, "features"):
            model.predict(invalid)

    def test_features_use_section_values(self):
        features = extract_packing_features({"sections": [
            {"entropy": 8.0, "is_high_entropy": True, "is_discrepancy_suspicious": True,
             "raw_size": 0, "virtual_size": 8192},
            {"entropy": 4.0, "is_high_entropy": False, "is_discrepancy_suspicious": False,
             "raw_size": 512, "virtual_size": 512},
        ]})
        self.assertEqual(features, {
            "section_count": 0.125, "high_entropy_fraction": 0.5,
            "max_entropy": 1.0, "suspicious_geometry_fraction": 0.5,
            "zero_raw_fraction": 0.5,
        })

    def test_persistence_and_invalid_model(self):
        model = PackingClassifierModel()
        model.fit([(dict.fromkeys(FEATURES, 0.0), "unpacked"),
                   (dict.fromkeys(FEATURES, 1.0), "UPX")])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            model.save(path)
            self.assertEqual(PackingClassifierModel.load(path).centroids, model.centroids)
            with self.assertRaises(FileExistsError):
                model.save(path)
            path.write_text('{"version":1,"features":[],"centroids":{}}')
            with patch("core.packing_model.MODEL_PATH", path):
                result = assess_packing({"sections": []})
            self.assertEqual(result["status"], "unavailable")
            self.assertIn("Cannot load", result["message"])

    def test_dataset_reproduces_shipped_model_and_metrics(self):
        root = Path(__file__).resolve().parent.parent
        dataset = json.loads((root / "data/packing_public.json").read_text())
        metrics = json.loads((root / "data/packing_public_metrics.json").read_text())
        model, result = train_dataset(dataset)
        self.assertEqual(result, metrics)
        self.assertEqual(model.centroids, PackingClassifierModel.load(
            root / "models/packing_model.json").centroids)
        self.assertEqual(result["test_samples"], 14)

    def test_public_dataset_projects_and_pairs_do_not_cross_splits(self):
        root = Path(__file__).resolve().parent.parent
        dataset = json.loads((root / "data/packing_public.json").read_text())
        samples = dataset["samples"]
        train_projects = {row["project"] for row in samples if row["split"] == "train"}
        test_projects = {row["project"] for row in samples if row["split"] == "test"}
        self.assertEqual(train_projects & test_projects, set())
        self.assertEqual(len(train_projects), 10)
        self.assertEqual(len(test_projects), 4)
        for group in {row["group_sha256"] for row in samples}:
            pair = [row for row in samples if row["group_sha256"] == group]
            self.assertEqual(len(pair), 2)
            self.assertEqual({row["label"] for row in pair}, {"UPX", "unpacked"})
            self.assertEqual(len({row["split"] for row in pair}), 1)

    def test_dataset_rejects_project_leakage(self):
        root = Path(__file__).resolve().parent.parent
        dataset = json.loads((root / "data/packing_public.json").read_text())
        train_row = next(row for row in dataset["samples"] if row["split"] == "train")
        test_row = next(row for row in dataset["samples"] if row["split"] == "test")
        test_row["project"] = train_row["project"]
        with self.assertRaisesRegex(ValueError, "project overlaps"):
            train_dataset(dataset)

    def test_dataset_rejects_split_leakage_and_duplicates(self):
        root = Path(__file__).resolve().parent.parent
        dataset = json.loads((root / "data/packing_baseline.json").read_text())
        dataset["samples"][0]["split"] = "test"
        with self.assertRaisesRegex(ValueError, "overlaps"):
            train_dataset(dataset)
        dataset["samples"][0]["split"] = "train"
        dataset["samples"][1]["sha256"] = dataset["samples"][0]["sha256"]
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            train_dataset(dataset)


if __name__ == "__main__":
    unittest.main()
