"""Adapt CAPE's static evidence only; never convert dynamic findings into labels."""

from training.legacy.legacy_behavior_analysis import MAX_VALUE_LENGTH


def static_evidence(report):
    target = report.get("target", {}).get("file")
    if not isinstance(target, dict):
        raise ValueError("CAPE report is missing target file metadata")
    strings = target.get("strings")
    pe = target.get("pe")
    if not isinstance(strings, list) or not isinstance(pe, dict) or not isinstance(pe.get("imports"), dict):
        raise ValueError("CAPE static strings or normal PE imports are unavailable")
    evidence = []
    for index, value in enumerate(strings):
        if not isinstance(value, str):
            raise ValueError(f"CAPE string {index} is not text")
        evidence.append({
            "id": f"s{index}",
            "source": f"target.file.strings[{index}]",
            "offset": None,
            "encoding": None,
            "value": value[:MAX_VALUE_LENGTH],
            "truncated": len(value) > MAX_VALUE_LENGTH,
            "categories": [],
            "model_suspicious": False,
        })
    index = 0
    for key, library in pe["imports"].items():
        if not isinstance(library, dict) or not isinstance(library.get("imports"), list):
            raise ValueError(f"Invalid CAPE library: {key}")
        for symbol_index, symbol in enumerate(library["imports"]):
            if not isinstance(symbol, dict):
                raise ValueError(f"Invalid import in {key}")
            evidence.append({
                "id": f"imports{index}",
                "source": f"target.file.pe.imports[{key!r}].imports[{symbol_index}]",
                "value": {"dll": library.get("dll"), "name": symbol.get("name"),
                          "ordinal": symbol.get("ordinal"), "forwarder": None},
            })
            index += 1
    digest = target.get("sha256")
    return digest, evidence
