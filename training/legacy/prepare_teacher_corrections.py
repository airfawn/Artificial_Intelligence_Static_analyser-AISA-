"""Prepare teacher corrections for responses that cite nonexistent evidence IDs."""

import argparse
import json
from pathlib import Path
import sys

from training.legacy.legacy_behavior_analysis import validate_analysis


def build_corrections(packet, response):
    expected = {}
    for path in sorted(packet.glob("batch-*.json")):
        for case in json.loads(path.read_text(encoding="utf-8"))["cases"]:
            case_id = case["case_id"]
            if case_id in expected:
                raise ValueError(f"Duplicate input case: {case_id}")
            expected[case_id] = case
    if not isinstance(response, dict) or set(response) != {"cases"} or not isinstance(response["cases"], list):
        raise ValueError("Response must contain a cases array")
    seen = set()
    corrections = []
    for case in response["cases"]:
        case_id = case.get("case_id")
        if case_id not in expected or case_id in seen:
            raise ValueError(f"Unexpected or duplicate case: {case_id}")
        seen.add(case_id)
        evidence = expected[case_id]["evidence"]
        allowed = {entry["id"]: entry for entry in evidence}
        try:
            validate_analysis(case.get("analysis"), allowed)
        except RuntimeError as exc:
            corrections.append({
                "case_id": case_id, "validation_error": str(exc),
                "evidence": evidence, "existing_response": case.get("analysis"),
            })
    if seen != set(expected):
        raise ValueError(f"Missing cases: {sorted(set(expected) - seen)}")
    return {"cases": corrections}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet")
    parser.add_argument("response")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        response = json.loads(Path(args.response).read_text(encoding="utf-8"))
        result = build_corrections(Path(args.packet), response)
        if not result["cases"]:
            raise ValueError("No invalid cases found")
        with Path(args.output).open("x", encoding="utf-8") as file:
            json.dump(result, file, indent=2, ensure_ascii=True)
            file.write("\n")
        print(f"Prepared corrections for {len(result['cases'])} cases in {args.output}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Correction preparation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
