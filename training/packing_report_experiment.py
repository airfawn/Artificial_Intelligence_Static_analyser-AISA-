"""Train an undeployed packing candidate using weak UPX markers in CAPE reports."""

import argparse
import hashlib
import json
import math
from pathlib import Path

from core.packing_model import extract_packing_features
from training.packing_baseline import train_dataset, write_json


def report_features(report):
    target = report.get("target", {}).get("file", {})
    pe = target.get("pe")
    sections = pe.get("sections") if isinstance(pe, dict) else None
    if not isinstance(sections, list) or not sections:
        return None
    names = {str(s.get("name", "")).strip("\x00").lower()
             for s in sections if isinstance(s, dict)}
    if not {"upx0", "upx1"}.issubset(names):
        return None
    converted = []
    for section in sections:
        if not isinstance(section, dict):
            raise ValueError("Invalid CAPE section")
        try:
            virtual = int(section["virtual_size"], 0)
            raw = int(section["size_of_data"], 0)
            entropy = float(section["entropy"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Invalid CAPE section features") from exc
        if virtual < 0 or raw < 0 or not math.isfinite(entropy) or not 0 <= entropy <= 8:
            raise ValueError("CAPE section features are out of range")
        # CAPE rounds entropy to two decimals, so 7.00 cannot determine >7.
        if entropy == 7.0:
            return None
        suspicious = (raw == 0 and virtual > 0x1000) or (
            raw > 0 and virtual / raw >= 3 and virtual - raw > 0x2000
        )
        converted.append({
            "virtual_size": virtual, "raw_size": raw, "entropy": entropy,
            "is_high_entropy": entropy > 7.0,
            "is_discrepancy_suspicious": suspicious,
        })
    return extract_packing_features({"sections": converted})


def experiment(dataset, manifest_path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("records"), list):
        raise ValueError("Invalid CAPE manifest")
    root = manifest_path.resolve().parent
    rows = list(dataset["samples"])
    known = {row["sha256"] for row in rows}
    added = []
    for record in manifest["records"]:
        path = (root / record["file"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"Invalid report path: {record['file']}")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != record["sha256"]:
            raise ValueError(f"Report checksum mismatch: {record['file']}")
        report = json.loads(payload)
        features = report_features(report)
        if features is None:
            continue
        digest = report.get("target", {}).get("file", {}).get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(
            c not in "0123456789abcdef" for c in digest
        ):
            raise ValueError(f"Invalid sample SHA-256: {record['file']}")
        if digest in known:
            continue
        known.add(digest)
        added.append({
            "split": "train", "label": "UPX", "group_sha256": digest,
            "sha256": digest, "features": features,
            "weak_label": "CAPE static section names UPX0 and UPX1",
            "source_report": record["file"], "report_sha256": record["sha256"],
        })
    _, baseline_metrics = train_dataset(dataset)
    if not added:
        raise ValueError("No usable weak UPX markers found; candidate not trained")
    candidate, candidate_metrics = train_dataset({**dataset, "samples": rows + added})
    return candidate, {
        "baseline": baseline_metrics,
        "candidate": candidate_metrics,
        "added_weak_upx_samples": len(added),
        "weak_samples": added,
        "limitations": (
            "UPX section names are spoofable and do not verify packing. CAPE entropy is rounded. "
            "No new unpacked labels or independently labeled CAPE holdout are available. "
            "The original test split was used for earlier model selection and is not independent. "
            "Do not deploy based on these results."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    args = parser.parse_args()
    if args.model.resolve() == args.metrics.resolve() or args.model.exists() or args.metrics.exists():
        parser.error("Model and metrics output paths must not exist")
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    candidate, metrics = experiment(dataset, args.manifest)
    candidate.save(args.model)
    write_json(args.metrics, metrics)
    print(json.dumps({key: value for key, value in metrics.items() if key != "weak_samples"}, indent=2))


if __name__ == "__main__":
    main()
