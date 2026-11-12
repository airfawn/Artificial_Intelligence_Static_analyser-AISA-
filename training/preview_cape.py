"""Preview CAPE-derived static evidence IDs for an analyst review."""

import argparse
import json
from pathlib import Path
import sys

from core.behavior_analysis import prepare_evidence
from training.cape_adapter import static_evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="CAPE JSON report")
    args = parser.parse_args(argv)
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        digest, evidence = static_evidence(report)
        _, selected, _, prompt = prepare_evidence(evidence)
        print(json.dumps({
            "source_sha256": digest,
            "entries_available": len(evidence),
            "entries_selected": len(selected),
            "limitations": [
                "Only CAPE static strings and normal imports are used.",
                "String offsets, encoding and AISA string classifications are unavailable.",
                "Dynamic behavior and dataset partition are not used as static evidence or labels.",
            ],
            "selected_evidence": selected,
            "model_prompt": prompt,
        }, indent=2, ensure_ascii=True))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Preview failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
