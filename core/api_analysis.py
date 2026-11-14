"""Offline, evidence-linked analysis using learned import frequencies."""

import argparse
import json
from pathlib import Path
import sys

from .api_knowledge import CAPABILITIES, PATTERNS, pattern_matches

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "api_frequency_model.json"
LIMITATIONS = [
    "Imports are declared dependencies, not proof of execution or a malware verdict.",
    "Frequencies are from a small, biased report corpus; they are not probabilities of maliciousness.",
    "CAPE family labels are automated, unverified, and may have very few samples.",
    "Training reports contain normal imports only; runtime-resolved APIs may be missing.",
    "Capability descriptions and combinations are curated possibilities, not learned actions.",
    "Names are matched without checking DLL identity; ordinal-only imports cannot be analyzed.",
    "The corpus has not been independently evaluated for malware detection.",
]


def load_model(path=MODEL_PATH):
    with path.open(encoding="utf-8") as file:
        model = json.load(file)
    if not isinstance(model, dict) or model.get("version") != 1:
        raise ValueError("Unsupported API frequency model")
    if any(not isinstance(model.get(field), dict)
           for field in ("sample_counts", "imports", "patterns", "cooccurrences")):
        raise ValueError("Invalid API frequency model")
    for label in ("malware", "benign"):
        total = model.get("sample_counts", {}).get(label)
        if not isinstance(total, int) or isinstance(total, bool) or total <= 0:
            raise ValueError(f"Invalid {label} sample count")
        for field in ("imports", "patterns", "cooccurrences"):
            values = model.get(field, {}).get(label)
            if not isinstance(values, dict) or any(
                not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool)
                or not 0 <= value <= total for key, value in values.items()
            ):
                raise ValueError(f"Invalid {label} {field} statistics")
    families = model.get("weak_families")
    if not isinstance(families, dict):
        raise ValueError("Invalid weak family statistics")
    for family, group in families.items():
        if not isinstance(family, str) or not isinstance(group, dict):
            raise ValueError("Invalid weak family statistics")
        total = group.get("samples")
        values = group.get("imports")
        if not isinstance(total, int) or isinstance(total, bool) or not 0 < total <= model["sample_counts"]["malware"] \
                or not isinstance(values, dict) or any(
                    not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool)
                    or not 0 <= value <= total for key, value in values.items()
                ):
            raise ValueError(f"Invalid weak family statistics: {family}")
    return model


def analyze_report(report, model=None):
    if not isinstance(report, dict) or report.get("status") != "complete":
        raise ValueError("A complete collection report is required")
    apis = report.get("apis")
    if not isinstance(apis, dict):
        raise ValueError("Report is missing API tables")
    model = load_model() if model is None else model
    names = {}
    for table in ("imports", "delay_imports"):
        entries = apis.get(table)
        if not isinstance(entries, list):
            raise ValueError(f"API table {table} is unavailable")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"Invalid {table} entry at index {index}")
            name = entry.get("name")
            if name is None:
                continue
            if not isinstance(name, str):
                raise ValueError(f"Invalid {table} name at index {index}")
            if name:
                names.setdefault(name.lower(), []).append({
                    "table": table, "index": index, "name": name, "dll": entry.get("dll"),
                })
    totals = model["sample_counts"]
    flagged = []
    for name, evidence in names.items():
        malware = model["imports"]["malware"].get(name, 0)
        benign = model["imports"]["benign"].get(name, 0)
        difference = malware / totals["malware"] - benign / totals["benign"]
        if name not in CAPABILITIES and not (malware >= 3 and difference >= 0.15):
            continue
        families = [
            {"label": family, "count": group["imports"][name], "samples": group["samples"]}
            for family, group in model["weak_families"].items() if name in group["imports"]
        ]
        flagged.append({
            "name": name, "evidence": evidence,
            "suggestion": CAPABILITIES.get(name, "More common in this malware partition; its function is not described here."),
            "malware_reports": malware, "malware_total": totals["malware"],
            "benign_reports": benign, "benign_total": totals["benign"],
            "weak_family_counts": families,
        })
    flagged.sort(key=lambda item: (
        -(item["malware_reports"] / item["malware_total"] - item["benign_reports"] / item["benign_total"]),
        item["name"],
    ))
    patterns = []
    for key, pattern in PATTERNS.items():
        if not pattern_matches(names, pattern):
            continue
        evidence = [ref for group in pattern["groups"] for name in group
                    for ref in names.get(name, [])]
        patterns.append({
            "id": key, "suggestion": pattern["description"], "evidence": evidence,
            "malware_reports": model["patterns"]["malware"].get(key, 0),
            "malware_total": totals["malware"],
            "benign_reports": model["patterns"]["benign"].get(key, 0),
            "benign_total": totals["benign"],
        })
    associations = []
    for pair, malware in model["cooccurrences"]["malware"].items():
        parts = pair.split("|")
        if len(parts) != 2 or not all(name in names for name in parts):
            continue
        benign = model["cooccurrences"]["benign"].get(pair, 0)
        difference = malware / totals["malware"] - benign / totals["benign"]
        if malware < 3 or difference < 0.15:
            continue
        associations.append({
            "names": parts, "evidence": [ref for name in parts for ref in names[name]],
            "malware_reports": malware, "malware_total": totals["malware"],
            "benign_reports": benign, "benign_total": totals["benign"],
            "suggestion": "These imports co-occurred in the corpus; no interaction or behavior is established.",
        })
    associations.sort(key=lambda item: (
        -(item["malware_reports"] / item["malware_total"] - item["benign_reports"] / item["benign_total"]),
        item["names"],
    ))
    metadata = report.get("pe_metadata", {})
    analyzed = report.get("analyzed_file", {})
    if not isinstance(metadata, dict) or not isinstance(analyzed, dict):
        raise ValueError("Invalid report file metadata")
    original_hashes = metadata.get("hashes", {})
    analyzed_hashes = analyzed.get("hashes", {})
    if not isinstance(original_hashes, dict) or not isinstance(analyzed_hashes, dict):
        raise ValueError("Invalid report file hashes")
    return {
        "status": "experimental",
        "method": "offline_api_frequency",
        "source_sha256": original_hashes.get("sha256"),
        "analyzed_sha256": analyzed_hashes.get("sha256"),
        "flagged_imports": flagged,
        "patterns": patterns,
        "observed_associations": associations,
        "summary": ("Potential capabilities only; no malware type or intent can be established from imports."
                    if flagged or patterns else
                    "No supported API indicators found; the analyzer cannot determine a verdict."),
        "limitations": LIMITATIONS,
        "model_provenance": {
            "dataset": model.get("dataset"), "revision": model.get("revision"),
            "manifest_sha256": model.get("manifest_sha256"), "sample_counts": totals,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.report.open(encoding="utf-8") as file:
            report = json.load(file)
        result = analyze_report(report)
        with args.output.open("x", encoding="utf-8") as file:
            json.dump(result, file, indent=2, ensure_ascii=True)
            file.write("\n")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"API analysis failed: {exc}", file=sys.stderr)
        return 1
    print(f"API analysis saved to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
