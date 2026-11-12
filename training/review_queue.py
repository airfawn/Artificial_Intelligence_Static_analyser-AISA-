"""Create a review queue from downloaded CAPE reports and export approved reviews."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from core.behavior_analysis import prepare_evidence
from training.cape_adapter import static_evidence
from training.prepare_reviewed import prepare


def build_queue(manifest_path):
    root = manifest_path.resolve().parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("records"), list):
        raise ValueError("Invalid dataset manifest")
    items = []
    seen = {}
    for record in manifest["records"]:
        relative = record["file"]
        report_path = (root / relative).resolve()
        if not report_path.is_relative_to(root) or not report_path.is_file():
            raise ValueError(f"Invalid report path: {relative}")
        payload = report_path.read_bytes()
        file_digest = hashlib.sha256(payload).hexdigest()
        if file_digest != record["sha256"]:
            raise ValueError(f"Report checksum mismatch: {relative}")
        report = json.loads(payload)
        digest, evidence = static_evidence(report)
        if not isinstance(digest, str) or len(digest) != 64 or any(
            c not in "0123456789abcdef" for c in digest.lower()
        ):
            raise ValueError(f"Invalid sample SHA-256: {relative}")
        digest = digest.lower()
        item = {
            "report_kind": "cape",
            "report": str(report_path),
            "report_sha256": file_digest,
            "sample_sha256": digest,
            "dataset_partition": record.get("dataset_partition"),
            "status": "pending",
            "split": None,
            "reviewer": None,
            "chosen": None,
            "rejected": None,
            "preference_reason": None,
        }
        if digest in seen:
            item["status"] = "blocked"
            item["blocked_reason"] = f"Duplicate sample; first report: {seen[digest]}"
            items.append(item)
            continue
        seen[digest] = str(report_path)
        try:
            _, selected, _, prompt = prepare_evidence(evidence)
        except RuntimeError as exc:
            item["status"] = "blocked"
            item["blocked_reason"] = str(exc)
        else:
            item["entries_available"] = len(evidence)
            item["selected_evidence"] = selected
            item["model_prompt"] = prompt
        items.append(item)
    return {
        "version": 1,
        "dataset": manifest.get("dataset"),
        "revision": manifest.get("revision"),
        "instructions": (
            "Pending entries are not reviewed. For each reviewable item, select a split, "
            "provide a reviewer and evidence-supported chosen analysis, and change status to reviewed. "
            "Optional rejected text requires a preference reason. Assign related families to the same split."
        ),
        "items": items,
    }


def approved_records(queue):
    if not isinstance(queue, dict) or queue.get("version") != 1 or not isinstance(queue.get("items"), list):
        raise ValueError("Invalid review queue")
    approved = []
    counts = {"pending": 0, "blocked": 0, "reviewed": 0}
    for item in queue["items"]:
        if not isinstance(item, dict) or item.get("status") not in counts:
            raise ValueError("Invalid review queue status")
        status = item["status"]
        counts[status] += 1
        if status != "reviewed":
            continue
        if item.get("report_kind") != "cape":
            raise ValueError("Invalid report kind in queue")
        path = Path(item["report"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["report_sha256"]:
            raise ValueError(f"Report changed since queue creation: {path}")
        record = {key: item[key] for key in ("report_kind", "report", "split", "reviewer", "chosen")}
        if item.get("rejected") is not None:
            record["rejected"] = item["rejected"]
            record["preference_reason"] = item.get("preference_reason")
        approved.append(record)
    if not approved:
        raise ValueError("No reviewed entries to export")
    prepare(approved, Path.cwd())
    return approved, counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    create = subparsers.add_parser("create", help="Create a new, unreviewed queue")
    create.add_argument("manifest")
    create.add_argument("--output", required=True)
    export = subparsers.add_parser("export", help="Validate and export reviewed entries only")
    export.add_argument("queue")
    export.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "create":
            result = build_queue(Path(args.manifest))
            counts = {status: sum(item["status"] == status for item in result["items"])
                      for status in ("pending", "blocked")}
        else:
            result, counts = approved_records(json.loads(Path(args.queue).read_text(encoding="utf-8")))
        with Path(args.output).open("x", encoding="utf-8") as file:
            json.dump(result, file, indent=2, ensure_ascii=True)
            file.write("\n")
        print(f"Saved {args.output}; counts: {counts}")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f"Review queue failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
