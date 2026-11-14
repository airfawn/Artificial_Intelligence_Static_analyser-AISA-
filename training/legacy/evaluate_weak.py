"""Compare local model outputs with held-out, machine-generated weak labels."""

import argparse
import json
from pathlib import Path

from training.legacy.legacy_behavior_analysis import analysis_schema, query_model, validate_analysis


def heldout_cases(data):
    metadata = json.loads((data / "provenance.json").read_text(encoding="utf-8"))
    records = [record for record in metadata["records"] if record["split"] == "test"]
    examples = [
        json.loads(line)
        for line in (data / "test.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    if not examples or len(examples) != len(records):
        raise ValueError("Held-out examples do not match complete provenance")

    for record, example in zip(records, examples):
        messages = example["messages"]
        prompt = messages[1]["content"]
        evidence = json.loads(prompt.split("Evidence:\n", 1)[1])
        selected = {item["id"]: item for item in evidence}
        reference = json.loads(messages[2]["content"])
        validate_analysis(reference, selected)
        yield record, messages, selected, reference


def assess(record, reference, analysis, selected):
    validate_analysis(analysis, selected)
    expected = {value for item in reference["hypotheses"] for value in item["evidence_ids"]}
    actual = {value for item in analysis["hypotheses"] for value in item["evidence_ids"]}
    return {
        "sha256": record["sha256"], "source_partition": record["partition"],
        "reference": reference, "valid": True, "analysis": analysis,
        "reference_evidence_count": len(expected),
        "matching_reference_evidence_count": len(expected & actual),
    }


def evaluate(data, model_path, adapter_path):
    from mlx_lm import generate, load
    from mlx_lm.sample_utils import make_sampler

    cases = list(heldout_cases(data))
    model, tokenizer = load(str(model_path), adapter_path=str(adapter_path) if adapter_path else None)
    results = []
    for record, messages, selected, reference in cases:
        chat = tokenizer.apply_chat_template(
            messages[:2], tokenize=False, add_generation_prompt=True, enable_thinking=False,
        )
        text = generate(model, tokenizer, prompt=chat, max_tokens=1024, sampler=make_sampler(temp=0))
        try:
            analysis = json.loads(text)
            result = assess(record, reference, analysis, selected)
        except (json.JSONDecodeError, RuntimeError) as exc:
            result = {
                "sha256": record["sha256"], "source_partition": record["partition"],
                "reference": reference, "valid": False, "error": str(exc),
            }
        result["raw_response"] = text
        results.append(result)
        print(f"Evaluated {len(results)}/{len(cases)}", flush=True)
    return evaluation_result(results, base_model=str(model_path),
                             adapter=str(adapter_path) if adapter_path else None)


def evaluate_ollama(data, model, port):
    cases = list(heldout_cases(data))
    results = []
    for record, messages, selected, reference in cases:
        try:
            analysis = query_model(
                messages[1]["content"], analysis_schema(selected), model=model,
                endpoint=f"http://127.0.0.1:{port}/api/chat",
            )
            result = assess(record, reference, analysis, selected)
        except (OSError, ValueError, RuntimeError) as exc:
            result = {
                "sha256": record["sha256"], "source_partition": record["partition"],
                "reference": reference, "valid": False, "error": str(exc),
            }
            print(f"Case {len(results) + 1} failed: {exc}", flush=True)
        results.append(result)
        print(f"Evaluated {len(results)}/{len(cases)}", flush=True)
    return evaluation_result(results, ollama_model=model)


def evaluation_result(results, **model):
    return {
        **model,
        "warning": (
            "References and source labels are unreviewed weak labels, not ground truth. "
            "Evidence overlap measures agreement with the teacher, not correctness. "
            "Exact-evidence grouping cannot rule out related families across splits."
        ),
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--model", type=Path)
    group.add_argument("--ollama-model")
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or (args.ollama_model and args.adapter):
        parser.error("port must be valid; --adapter is only for MLX models")
    try:
        if args.output.exists():
            raise FileExistsError(f"Output already exists: {args.output}")
        result = (evaluate_ollama(args.data, args.ollama_model, args.port)
                  if args.ollama_model else evaluate(args.data, args.model, args.adapter))
        with args.output.open("x", encoding="utf-8") as file:
            json.dump(result, file, indent=2, ensure_ascii=True)
            file.write("\n")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        parser.exit(1, f"Evaluation failed: {exc}\n")


if __name__ == "__main__":
    main()
