"""Experimental nearest-centroid classifier for PE packing features.

The classifier is deliberately independent of the packing gate: predictions
must be evaluated on representative, held-out samples before they can be used
to decide whether a file is safe to analyze or which unpacker to run.
"""

import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple


FEATURES = (
    "section_count",
    "high_entropy_fraction",
    "max_entropy",
    "suspicious_geometry_fraction",
    "zero_raw_fraction",
)
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "packing_model.json"


def extract_packing_features(packing: Mapping[str, Any]) -> Dict[str, float]:
    sections = packing["sections"]
    count = len(sections)
    if not count:
        return {name: 0.0 for name in FEATURES}
    return {
        "section_count": min(count / 16.0, 1.0),
        "high_entropy_fraction": sum(bool(s["is_high_entropy"]) for s in sections) / count,
        "max_entropy": max(s["entropy"] for s in sections) / 8.0,
        "suspicious_geometry_fraction": sum(
            bool(s["is_discrepancy_suspicious"]) for s in sections
        ) / count,
        "zero_raw_fraction": sum(
            s["raw_size"] == 0 and s["virtual_size"] > 0 for s in sections
        ) / count,
    }


def _validate_features(features: Mapping[str, float]) -> None:
    if set(features) != set(FEATURES) or any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not math.isfinite(value) or not 0 <= value <= 1
        for value in features.values()
    ):
        raise ValueError("Packing features must contain finite values between 0 and 1")


class PackingClassifierModel:
    """Nearest-centroid model; a new instance has no learned classes."""

    def __init__(self) -> None:
        self.centroids: Dict[str, Dict[str, float]] = {}

    def fit(self, examples: Iterable[Tuple[Mapping[str, float], str]]) -> None:
        groups: Dict[str, List[Mapping[str, float]]] = {}
        for features, label in examples:
            if not isinstance(label, str) or not label.strip():
                raise ValueError("Each packing example must have a non-empty label")
            _validate_features(features)
            groups.setdefault(label, []).append(features)
        if len(groups) < 2:
            raise ValueError("Training requires at least two distinct packing labels")
        self.centroids = {
            label: {
                name: sum(example[name] for example in group) / len(group)
                for name in FEATURES
            }
            for label, group in groups.items()
        }

    def predict(self, features: Mapping[str, float]) -> Dict[str, Any]:
        if not self.centroids:
            raise ValueError("Packing model is untrained")
        _validate_features(features)
        distances = {
            label: math.sqrt(sum((features[name] - center[name]) ** 2 for name in FEATURES))
            for label, center in self.centroids.items()
        }
        label = min(distances, key=lambda item: (distances[item], item))
        return {"label": label, "distance": distances[label]}

    def save(self, path: Path) -> None:
        if len(self.centroids) < 2:
            raise ValueError("Cannot save an untrained packing model")
        with path.open("x", encoding="utf-8") as file:
            json.dump({"version": 1, "features": list(FEATURES), "centroids": self.centroids},
                      file, indent=2, allow_nan=False)
            file.write("\n")

    @classmethod
    def load(cls, path: Path) -> "PackingClassifierModel":
        with path.open(encoding="utf-8") as file:
            data = json.load(file)
        if not isinstance(data, dict) or data.get("version") != 1 or data.get("features") != list(FEATURES):
            raise ValueError("Unsupported packing model format or feature schema")
        centroids = data.get("centroids")
        if not isinstance(centroids, dict) or len(centroids) < 2:
            raise ValueError("Packing model must contain at least two centroids")
        for label, features in centroids.items():
            if not isinstance(label, str) or not label.strip() or not isinstance(features, dict):
                raise ValueError("Invalid packing model centroid")
            _validate_features(features)
        model = cls()
        model.centroids = centroids
        return model

    def assess(self, packing: Mapping[str, Any]) -> Dict[str, Any]:
        features = extract_packing_features(packing)
        if not self.centroids:
            return {
                "status": "untrained",
                "message": "No packing model has been trained; the packing gate uses heuristics.",
                "features": features,
            }
        return {
            "status": "trained",
            "message": "Experimental closed-set prediction among trained labels only, not proof; "
                       "unknown packers cannot be identified and the packing gate uses heuristics.",
            "features": features,
            "prediction": self.predict(features),
        }


def assess_packing(packing: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        model = PackingClassifierModel.load(MODEL_PATH)
    except (OSError, ValueError) as exc:
        return {
            "status": "unavailable",
            "message": f"Cannot load packing model: {exc}; the packing gate uses heuristics.",
            "features": extract_packing_features(packing),
        }
    return model.assess(packing)
