"""Evaluate the fixed weighted packing score on the recorded test split."""

import argparse
import json
from pathlib import Path

from core.packing_score import THRESHOLD, WEIGHTS
from training.packing_baseline import train_dataset, write_json


def evaluate(dataset, reference):
    train_dataset(dataset)
    train_dataset(reference)
    original_rows = {row["sha256"]: row for row in reference["samples"]}
    new_rows = {row["sha256"]: row for row in dataset["samples"]}
    if original_rows.keys() != new_rows.keys():
        raise ValueError("Dataset sample hashes do not match the recorded reference")
    for digest, row in new_rows.items():
        source = original_rows[digest]
        if any(row.get(key) != source.get(key) for key in
               ("split", "project", "label", "group_sha256", "features")):
            raise ValueError(f"Dataset does not match reference for {digest}")
    confusion = {"UPX": {"above": 0, "not_above": 0},
                 "unpacked": {"above": 0, "not_above": 0}}
    for row in dataset["samples"]:
        if row["split"] != "test":
            continue
        score = row.get("weighted_score")
        if not isinstance(score, dict) or score.get("status") != "experimental" \
                or score.get("threshold") != THRESHOLD:
            raise ValueError("Missing or incompatible weighted score")
        value = score.get("score")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise ValueError("Invalid weighted score")
        indicators = score.get("indicators")
        if score.get("weights") != WEIGHTS or not isinstance(indicators, dict) \
                or set(indicators) != set(WEIGHTS) \
                or any(not isinstance(value, bool) for value in indicators.values()):
            raise ValueError("Invalid weighted score indicators or weights")
        expected = round(sum(WEIGHTS[name] for name, present in indicators.items() if present), 4)
        if value != expected:
            raise ValueError("Weighted score does not match its indicators")
        if score.get("above_threshold") is not (value > THRESHOLD):
            raise ValueError("Weighted score threshold result is inconsistent")
        confusion[row["label"]]["above" if value > THRESHOLD else "not_above"] += 1
    tp = confusion["UPX"]["above"]
    tn = confusion["unpacked"]["not_above"]
    total = sum(sum(counts.values()) for counts in confusion.values())
    return {
        "threshold": THRESHOLD, "comparison": "strictly greater than",
        "test_samples": total, "correct": tp + tn, "accuracy": (tp + tn) / total,
        "confusion_matrix": confusion,
        "limitations": dataset["limitations"] + " This split was used for earlier model evaluation; "
                       "it is not a fresh independent test of the overall workflow.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.dataset.open(encoding="utf-8") as file:
        dataset = json.load(file)
    with args.reference.open(encoding="utf-8") as file:
        reference = json.load(file)
    result = evaluate(dataset, reference)
    write_json(args.output, result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
