"""Build an offline per-sample API frequency model from a CAPE report manifest."""

import argparse
from collections import Counter
import hashlib
from itertools import combinations
import json
from pathlib import Path

from core.api_knowledge import CAPABILITIES, PATTERNS, pattern_matches


def import_names(target):
    pe = target.get("pe")
    imports = pe.get("imports") if isinstance(pe, dict) else None
    if not isinstance(imports, dict):
        return None
    names = set()
    for library in imports.values():
        if not isinstance(library, dict) or not isinstance(library.get("imports"), list):
            raise ValueError("Invalid CAPE import library")
        for symbol in library["imports"]:
            if not isinstance(symbol, dict):
                raise ValueError("Invalid CAPE import entry")
            name = symbol.get("name")
            if name is not None and not isinstance(name, str):
                raise ValueError("Invalid CAPE import name")
            if name:
                names.add(name.lower())
    return names


def train(manifest_path):
    root = manifest_path.resolve().parent
    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("records"), list):
        raise ValueError("Invalid report manifest")
    counts = {label: Counter() for label in ("malware", "benign")}
    totals = Counter()
    pairs = {label: Counter() for label in counts}
    cooccurrences = {label: Counter() for label in counts}
    families = {}
    seen = {}
    missing = duplicates = 0
    for record in manifest["records"]:
        label = record["dataset_partition"]
        if label not in counts:
            raise ValueError(f"Unknown source partition: {label}")
        path = (root / record["file"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"Invalid report path: {record['file']}")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != record["sha256"]:
            raise ValueError(f"Report checksum mismatch: {record['file']}")
        report = json.loads(payload)
        target = report.get("target", {}).get("file")
        if not isinstance(target, dict):
            raise ValueError(f"Missing target metadata: {record['file']}")
        digest = target.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError(f"Invalid sample SHA-256: {record['file']}")
        digest = digest.lower()
        names = import_names(target)
        if digest in seen:
            previous_label, previous_usable = seen[digest]
            if previous_label != label:
                raise ValueError(f"Sample appears in conflicting partitions: {record['file']}")
            duplicates += 1
            if previous_usable or names is None:
                continue
            missing -= 1
        seen[digest] = (label, names is not None)
        if names is None:
            missing += 1
            continue
        totals[label] += 1
        counts[label].update(names)
        cooccurrences[label].update(
            "|".join(pair) for pair in combinations(sorted(names & CAPABILITIES.keys()), 2)
        )
        for key, pattern in PATTERNS.items():
            if pattern_matches(names, pattern):
                pairs[label][key] += 1
        family = target.get("cape_type")
        if label == "malware" and isinstance(family, str) and family.strip():
            family = family.strip()
            group = families.setdefault(family, {"samples": 0, "imports": Counter()})
            group["samples"] += 1
            group["imports"].update(names)
    if not all(totals[label] for label in counts):
        raise ValueError("Both partitions must contain reports with import tables")
    return {
        "version": 1,
        "dataset": manifest.get("dataset"),
        "revision": manifest.get("revision"),
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "sample_counts": dict(totals),
        "skipped_missing_imports": missing,
        "duplicate_reports": duplicates,
        "imports": {label: dict(sorted(counter.items())) for label, counter in counts.items()},
        "patterns": {label: dict(counter) for label, counter in pairs.items()},
        "cooccurrences": {label: dict(sorted(counter.items())) for label, counter in cooccurrences.items()},
        "weak_families": {
            family: {"samples": group["samples"], "imports": dict(sorted(group["imports"].items()))}
            for family, group in sorted(families.items())
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    model = train(args.manifest)
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(model, file, indent=2, ensure_ascii=True)
        file.write("\n")
    print(f"Saved {args.output}; sample counts: {model['sample_counts']}; "
          f"missing imports: {model['skipped_missing_imports']}; duplicates: {model['duplicate_reports']}")
    for label in ("malware", "benign"):
        common = sorted(model["imports"][label].items(), key=lambda item: (-item[1], item[0]))[:10]
        print(f"Most common {label} imports (reports): {common}")
    for family, group in model["weak_families"].items():
        common = sorted(group["imports"].items(), key=lambda item: (-item[1], item[0]))[:10]
        print(f"Unverified {family} ({group['samples']} reports): {common}")


if __name__ == "__main__":
    main()
