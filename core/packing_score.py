"""Experimental, manually weighted packing indicators; not a probability."""

from typing import Any, Dict, List

from .packer_signatures import identify_packer


THRESHOLD = 0.6
WEIGHTS = {"section_name": 0.4, "size_discrepancy": 0.35, "high_entropy": 0.25}


def assess_packing_score(sections: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not sections:
        return {
            "status": "unavailable",
            "message": "No PE sections available for scoring.",
            "score": None,
            "threshold": THRESHOLD,
            "above_threshold": None,
        }
    matches = identify_packer(sections)["matches"]
    indicators = {
        "section_name": bool(matches),
        "size_discrepancy": any(
            s["is_discrepancy_suspicious"] and s["name"].lower() not in {".data", ".bss"}
            for s in sections
        ),
        "high_entropy": any(s["is_high_entropy"] for s in sections),
    }
    score = round(sum(WEIGHTS[name] for name, present in indicators.items() if present), 4)
    return {
        "status": "experimental",
        "score": score,
        "threshold": THRESHOLD,
        "above_threshold": score > THRESHOLD,
        "indicators": indicators,
        "weights": dict(WEIGHTS),
        "matched_packers": matches,
        "message": "Manually weighted heuristic, not a probability; the existing packing gate remains in effect.",
    }
