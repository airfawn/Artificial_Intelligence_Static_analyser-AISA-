"""Generate a small local UPX dataset and train an experimental baseline."""

import argparse
import hashlib
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path

from core.packing_model import PackingClassifierModel, extract_packing_features
from core.pe_analyzer import PEAnalyzer


FIXTURES = {
    "t32.exe": "train", "t64.exe": "train",
    "w32.exe": "test", "w64.exe": "test",
}


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _features(path):
    analyzer = PEAnalyzer(str(path))
    if not analyzer.is_valid_pe:
        raise ValueError(f"Not a valid PE: {path}")
    return extract_packing_features(analyzer.analyze_packing())


def create_dataset(fixture_dir, upx):
    version = subprocess.run([upx, "--version"], check=True, capture_output=True,
                             text=True, timeout=60).stdout.splitlines()[0]
    samples = []
    with tempfile.TemporaryDirectory(prefix="aisa-packing-data-") as directory:
        for name, split in FIXTURES.items():
            source = fixture_dir / name
            source_hash = _sha256(source)
            packed = Path(directory) / name
            subprocess.run([upx, "-o", str(packed), str(source)], check=True,
                           capture_output=True, timeout=60)
            subprocess.run([upx, "-t", str(packed)], check=True,
                           capture_output=True, timeout=60)
            for path, label in ((source, "unpacked"), (packed, "UPX")):
                samples.append({
                    "fixture": name,
                    "group_sha256": source_hash,
                    "sha256": _sha256(path),
                    "split": split,
                    "label": label,
                    "features": _features(path),
                })
    return {
        "version": 1,
        "source": "pip vendored distlib launchers; unpacked originals and UPX-packed copies",
        "upx_version": version,
        "limitations": "Four related launchers; test files are related to training files. "
                       "No other packers or independent executable families.",
        "samples": samples,
    }


def train_dataset(dataset):
    if not isinstance(dataset, dict) or dataset.get("version") != 1 or not isinstance(dataset.get("samples"), list):
        raise ValueError("Invalid packing dataset")
    groups = {}
    projects = {}
    hashes = {}
    splits = {"train": [], "test": []}
    for row in dataset["samples"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid dataset row")
        split, label, group, digest, features = (
            row.get("split"), row.get("label"), row.get("group_sha256"),
            row.get("sha256"), row.get("features"),
        )
        if split not in splits or label not in ("UPX", "unpacked"):
            raise ValueError("Invalid split or label")
        if any(not isinstance(value, str) or len(value) != 64
               or any(c not in "0123456789abcdef" for c in value) for value in (group, digest)):
            raise ValueError("Invalid sample or group SHA-256")
        if not isinstance(features, dict):
            raise ValueError("Invalid feature vector")
        if group in groups and groups[group] != split:
            raise ValueError("Source group overlaps train and test splits")
        project = row.get("project")
        if project is not None:
            if not isinstance(project, str) or not project.strip():
                raise ValueError("Invalid source project")
            if project in projects and projects[project] != split:
                raise ValueError("Source project overlaps train and test splits")
            projects[project] = split
        if digest in hashes:
            raise ValueError("Duplicate sample SHA-256")
        groups[group] = split
        hashes[digest] = split
        splits[split].append((features, label))
    if {label for _, label in splits["train"]} != {"UPX", "unpacked"} or \
       {label for _, label in splits["test"]} != {"UPX", "unpacked"}:
        raise ValueError("Both splits must include both labels")
    model = PackingClassifierModel()
    model.fit(splits["train"])
    confusion = {label: {"UPX": 0, "unpacked": 0} for label in ("UPX", "unpacked")}
    for features, label in splits["test"]:
        predicted = model.predict(features)["label"]
        confusion[label][predicted] += 1
    total = len(splits["test"])
    correct = sum(confusion[label][label] for label in confusion)
    return model, {
        "train_samples": len(splits["train"]),
        "test_samples": total,
        "correct": correct,
        "accuracy": correct / total,
        "confusion_matrix": confusion,
        "limitations": dataset.get("limitations"),
    }


def write_json(path, value):
    with path.open("x", encoding="utf-8") as file:
        json.dump(value, file, indent=2, allow_nan=False)
        file.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    generate.add_argument("--fixture-dir", type=Path, help="Directory containing pip distlib launchers")
    generate.add_argument("--upx", default="upx")
    generate.add_argument("--output", type=Path, required=True)
    train = commands.add_parser("train")
    train.add_argument("--dataset", type=Path, required=True)
    train.add_argument("--model", type=Path, required=True)
    train.add_argument("--metrics", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "generate":
        fixture_dir = args.fixture_dir
        if fixture_dir is None:
            spec = importlib.util.find_spec("pip")
            if spec is None or spec.origin is None:
                parser.error("pip not found; supply --fixture-dir")
            fixture_dir = Path(spec.origin).parent / "_vendor" / "distlib"
        write_json(args.output, create_dataset(fixture_dir, args.upx))
        print(f"Dataset saved to {args.output}")
    else:
        with args.dataset.open(encoding="utf-8") as file:
            dataset = json.load(file)
        model, metrics = train_dataset(dataset)
        if args.model.resolve() == args.metrics.resolve() or args.model.exists() or args.metrics.exists():
            parser.error("Model and metrics output paths must not exist")
        model.save(args.model)
        write_json(args.metrics, metrics)
        print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
