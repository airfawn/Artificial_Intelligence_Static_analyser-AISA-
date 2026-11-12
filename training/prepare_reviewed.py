"""Export human-reviewed collector reports for supervised and preference training."""

import argparse
import json
from pathlib import Path
import sys

from core.behavior_analysis import SYSTEM, prepare_evidence, prepare_evidence_prompt, validate_analysis
from training.cape_adapter import static_evidence


def prepare(records, base):
    supervised = {"train": [], "valid": [], "test": []}
    preferences = {"train": [], "valid": [], "test": []}
    seen = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"Record {index} must be an object")
        split = record.get("split")
        if split not in supervised:
            raise ValueError(f"Record {index} has an invalid split")
        if not isinstance(record.get("reviewer"), str) or not record["reviewer"].strip():
            raise ValueError(f"Record {index} requires a reviewer")
        kind = record.get("report_kind", "collector")
        if kind not in ("collector", "cape"):
            raise ValueError(f"Record {index} has an invalid report_kind")
        path = record.get("report")
        if not isinstance(path, str) or not path:
            raise ValueError(f"Record {index} requires a report path")
        report = json.loads((base / path).read_text(encoding="utf-8"))
        if kind == "cape":
            digest, evidence = static_evidence(report)
            _, _, selected, prompt = prepare_evidence(evidence)
        else:
            digest = report.get("pe_metadata", {}).get("hashes", {}).get("sha256")
            _, _, selected, prompt = prepare_evidence_prompt(report)
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError(f"Record {index} requires a SHA-256 sample hash")
        digest = digest.lower()
        if digest in seen:
            raise ValueError(f"Duplicate sample hash in record {index}: {digest}")
        seen.add(digest)
        chosen = record.get("chosen")
        validate_analysis(chosen, selected)
        chosen_text = json.dumps(chosen, ensure_ascii=True)
        messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
        supervised[split].append({
            "messages": messages + [{"role": "assistant", "content": chosen_text}],
        })
        rejected = record.get("rejected")
        if rejected is not None:
            if not isinstance(rejected, str) or not rejected.strip():
                raise ValueError(f"Record {index} rejected response must be nonempty text")
            reason = record.get("preference_reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"Record {index} requires a preference reason")
            preferences[split].append({
                "sample_sha256": digest,
                "reviewer": record["reviewer"],
                "messages": messages,
                "chosen": chosen_text,
                "rejected": rejected,
                "preference_reason": reason,
            })
    return supervised, preferences


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reviews", help="JSON array of reviewer-annotated collector reports")
    parser.add_argument("--output", required=True, help="New output directory")
    args = parser.parse_args(argv)
    try:
        source = Path(args.reviews).resolve()
        records = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(records, list) or not records:
            raise ValueError("Reviews must be a nonempty JSON array")
        supervised, preferences = prepare(records, source.parent)
        if not all(supervised[split] for split in supervised):
            raise ValueError("Reviewed train, valid, and test samples are all required")
        target = Path(args.output)
        target.mkdir(parents=True, exist_ok=False)
        for split in supervised:
            for name, entries in ((f"{split}.jsonl", supervised[split]),
                                  (f"{split}.preferences.jsonl", preferences[split])):
                with (target / name).open("x", encoding="utf-8") as file:
                    for entry in entries:
                        file.write(json.dumps(entry, ensure_ascii=True) + "\n")
        print(f"Prepared {len(records)} reviewed examples in {target}")
        print("Preference files are review data; no reinforcement learning has been run.")
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Preparation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
