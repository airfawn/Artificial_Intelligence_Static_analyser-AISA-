"""Prepare experimental local-teacher training data from CAPE reports."""

import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path

from training.legacy.legacy_behavior_analysis import (
    SYSTEM,
    analysis_schema,
    prepare_evidence,
    query_model,
    validate_analysis,
)
from training.legacy.cape_adapter import static_evidence
from training.legacy.guardrails import block_untrusted_llm


def split_for_evidence(evidence):
    values = sorted({
        json.dumps(item["value"], sort_keys=True, ensure_ascii=True)
        for item in evidence
    })
    if not values:
        raise ValueError("No static evidence available for grouping")
    digest = hashlib.sha256("\n".join(values).encode("utf-8")).digest()
    value = int.from_bytes(digest[:4], "big") % 100
    return "train" if value < 70 else "valid" if value < 85 else "test"


def teacher_prompt(prompt, report, partition):
    signatures = report.get("signatures", [])
    if not isinstance(signatures, list):
        raise ValueError("Invalid sandbox signatures")
    hints = []
    for signature in signatures[:20]:
        if not isinstance(signature, dict):
            raise ValueError("Invalid sandbox signature")
        name = signature.get("name", "")
        description = signature.get("description", "")
        if not isinstance(name, str) or not isinstance(description, str):
            raise ValueError("Invalid sandbox signature text")
        hints.append({"name": name[:100], "description": description[:200]})
    return (
        prompt + "\n\nWeak training hints, not evidence available to the student: " +
        json.dumps({"source_partition": partition, "sandbox_signatures": hints}, ensure_ascii=True) +
        "\nThe source partition and sandbox signatures may be wrong or unrelated to the "
        "provided static artifacts. Use them only to consider possibilities; never cite "
        "them or present their observed behavior as established by static evidence. "
        "Use only cited static evidence to support each hypothesis. If a hypothesis "
        "cannot be supported by those artifacts, omit it. Do not mention the hints, "
        "source partition, sandbox, or training data in the response."
    )


def prepare_records(manifest_path, limit_per_class):
    block_untrusted_llm()
    root = manifest_path.resolve().parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("records"), list):
        raise ValueError("Invalid dataset manifest")
    counts = {"malware": 0, "benign": 0}
    seen = set()
    records = []
    excluded = []
    for record in manifest["records"]:
        partition = record.get("dataset_partition")
        if partition not in counts:
            raise ValueError("Invalid source partition")
        if counts[partition] >= limit_per_class:
            continue
        path = (root / record["file"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("Invalid report path")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != record["sha256"]:
            raise ValueError(f"Report checksum mismatch: {record['file']}")
        report = json.loads(payload)
        try:
            digest, evidence = static_evidence(report)
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest.lower())):
                raise ValueError("Invalid sample SHA-256")
            digest = digest.lower()
            if digest in seen:
                raise ValueError("Duplicate sample SHA-256")
            split = split_for_evidence(evidence)
            _, _, selected, prompt = prepare_evidence(evidence)
        except (ValueError, RuntimeError) as exc:
            excluded.append({"file": record["file"], "reason": str(exc)})
            continue
        seen.add(digest)
        counts[partition] += 1
        records.append({
            "file": record["file"], "sha256": digest, "partition": partition,
            "split": split, "selected": selected, "prompt": prompt,
            "teacher_prompt": teacher_prompt(prompt, report, partition),
        })
    if any(count < limit_per_class for count in counts.values()):
        raise ValueError(f"Not enough usable reports: {counts}")
    if set(record["split"] for record in records) != {"train", "valid", "test"}:
        raise ValueError("The selected records do not cover all three splits")
    return manifest, records, excluded


def generate(manifest_path, output, limit_per_class, model, port, resume=False):
    block_untrusted_llm()
    manifest, records, excluded = prepare_records(manifest_path, limit_per_class)
    counts = {"train": 0, "valid": 0, "test": 0}
    generation = {
        "dataset": manifest.get("dataset"), "revision": manifest.get("revision"),
        "teacher": model,
    }
    provenance = []
    if resume:
        if (output / "provenance.json").exists():
            raise ValueError("The dataset is already complete")
        previous_generation = json.loads((output / "generation.json").read_text(encoding="utf-8"))
        if previous_generation != generation:
            raise ValueError("Checkpoint dataset or teacher does not match")
        partial = (output / "provenance.partial.jsonl").read_text(encoding="utf-8").splitlines()
        provenance = [json.loads(line) for line in partial]
        if len(provenance) > len(records):
            raise ValueError("Checkpoint contains more records than the requested dataset")
        previous_rows = {}
        for split in counts:
            path = output / f"{split}.jsonl"
            previous_rows[split] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for record, entry in zip(records, provenance):
            expected = {key: record[key] for key in ("file", "sha256", "partition", "split")}
            if entry != expected or counts[record["split"]] >= len(previous_rows[record["split"]]):
                raise ValueError("Checkpoint records do not match the requested dataset")
            row = previous_rows[record["split"]][counts[record["split"]]]
            if (row["messages"][0] != {"role": "system", "content": SYSTEM}
                    or row["messages"][1] != {"role": "user", "content": record["prompt"]}):
                raise ValueError("Checkpoint prompt has changed")
            validate_analysis(json.loads(row["messages"][2]["content"]), record["selected"])
            counts[record["split"]] += 1
        if any(len(previous_rows[split]) != counts[split] for split in counts):
            raise ValueError("Checkpoint labels and provenance do not match")
    else:
        output.mkdir(parents=True, exist_ok=False)
        with (output / "generation.json").open("x", encoding="utf-8") as file:
            json.dump(generation, file, indent=2)
    with ExitStack() as stack:
        files = {
            split: stack.enter_context((output / f"{split}.jsonl").open(
                "a" if resume else "x", encoding="utf-8",
            ))
            for split in counts
        }
        partial = stack.enter_context((output / "provenance.partial.jsonl").open(
            "a" if resume else "x", encoding="utf-8",
        ))
        for index, record in enumerate(records[len(provenance):], len(provenance) + 1):
            analysis = query_model(
                record["teacher_prompt"], analysis_schema(record["selected"]), model=model,
                endpoint=f"http://127.0.0.1:{port}/api/chat",
            )
            validate_analysis(analysis, record["selected"])
            example = {"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": record["prompt"]},
                {"role": "assistant", "content": json.dumps(analysis, ensure_ascii=True)},
            ]}
            file = files[record["split"]]
            file.write(json.dumps(example, ensure_ascii=True) + "\n")
            file.flush()
            counts[record["split"]] += 1
            entry = {key: record[key] for key in ("file", "sha256", "partition", "split")}
            provenance.append(entry)
            partial.write(json.dumps(entry) + "\n")
            partial.flush()
            print(f"Generated weak label {index}/{len(records)} ({record['split']})", flush=True)
    metadata = {
        "dataset": manifest.get("dataset"), "revision": manifest.get("revision"),
        "teacher": model, "records": provenance, "excluded": excluded,
        "warning": (
            "Machine-generated weak labels are not reviewed or ground truth. "
            "Exact-evidence grouping cannot rule out related families across splits."
        ),
    }
    with (output / "provenance.json").open("x", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)
    print("Split counts:", counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit-per-class", type=int, default=20)
    parser.add_argument("--teacher", default="qwen3:14b")
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--resume", action="store_true", help="Resume a validated incomplete dataset")
    args = parser.parse_args()
    if args.limit_per_class < 1 or not 1 <= args.port <= 65535:
        parser.error("limit-per-class and port must be positive")
    try:
        generate(args.manifest, args.output, args.limit_per_class, args.teacher, args.port, args.resume)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        parser.exit(1, f"Weak supervision failed: {exc}\n")


if __name__ == "__main__":
    main()
