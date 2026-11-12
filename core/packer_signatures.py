"""Conservative packer identification from PE section names."""

from typing import Any, Dict, List


SIGNATURES = {
    "UPX": {"upx0", "upx1", "upx2", ".upx"},
    "ASPack": {".aspack"},
    "MPRESS": {".mpress1", ".mpress2"},
    "FSG": {".fsg"},
    "Themida": {".themida"},
    "VMProtect": {".vmp0", ".vmp1"},
    "PECompact": {"pec1", "pec2"},
    "NsPack": {".nsp0"},
    "MEW": {"mew"},
    "Enigma": {".enigma"},
}


def identify_packer(sections: List[Dict[str, Any]]) -> Dict[str, Any]:
    names = {section["name"].lower() for section in sections}
    matches = [
        {"name": name, "section_names": sorted(names & signatures)}
        for name, signatures in SIGNATURES.items() if names & signatures
    ]
    return {
        "status": "identified" if len(matches) == 1 else "ambiguous" if matches else "unknown",
        "name": matches[0]["name"] if len(matches) == 1 else None,
        "matches": matches,
        "method": "section_names",
    }
