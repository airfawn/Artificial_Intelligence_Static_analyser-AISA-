"""Collect statically declared PE imports and exports, without interpreting behavior."""

from typing import Any, Dict, Optional

import pefile


def _decode(value: Optional[bytes]) -> Optional[str]:
    return value.decode("ascii", errors="backslashreplace") if value is not None else None


def collect_api_tables(pe: pefile.PE) -> Dict[str, Any]:
    """Return normal and delay imports and exports, with parse diagnostics."""
    result: Dict[str, Any] = {
        "imports": [],
        "delay_imports": [],
        "exports": [],
        "export_dll": None,
        "directories": {},
        "warnings": list(pe.get_warnings()),
        "limitations": (
            "Imports are declared dependencies, not proof of execution. "
            "Dynamically resolved or encrypted APIs may not appear in PE tables."
        ),
    }

    for label, constant, attribute in (
        ("imports", "IMAGE_DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_IMPORT"),
        ("delay_imports", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"),
        ("exports", "IMAGE_DIRECTORY_ENTRY_EXPORT", "DIRECTORY_ENTRY_EXPORT"),
    ):
        index = pefile.DIRECTORY_ENTRY[constant]
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        directory = directories[index] if index < len(directories) else None
        present = bool(directory and (directory.VirtualAddress or directory.Size))
        entries = getattr(pe, attribute, None)
        if not present:
            result["directories"][label] = {"status": "absent"}
            continue
        if not entries:
            result[label] = None
            result["directories"][label] = {
                "status": "unreadable",
                "message": f"{label} directory is present but could not be parsed; its contents are unknown.",
            }
            continue
        result["directories"][label] = {"status": "parsed"}
        if label == "exports":
            result["export_dll"] = _decode(entries.name)
            for symbol in entries.symbols:
                result["exports"].append({
                    "name": _decode(symbol.name),
                    "ordinal": symbol.ordinal,
                    "address_rva": symbol.address,
                    "forwarder": _decode(symbol.forwarder),
                })
        else:
            for library in entries:
                dll = _decode(library.dll)
                for symbol in library.imports:
                    result[label].append({
                        "dll": dll,
                        "name": _decode(symbol.name),
                        "ordinal": symbol.ordinal if symbol.import_by_ordinal else None,
                        "hint": symbol.hint,
                        "address": symbol.address,
                    })
    return result
