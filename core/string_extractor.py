"""
Native Binary String Extractor.
Extracts ASCII and UTF-16LE (Wide) strings from raw binary files cross-platform,
calculating byte offsets, encoding types, and Shannon entropy.
"""

import re
import math
from typing import List, Dict, Any, Generator


def calculate_string_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string (character distribution)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class StringExtractor:
    """Extracts strings directly from binary data across ASCII and UTF-16LE encodings."""

    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        # Printable ASCII: 0x20 (space) to 0x7E (~), plus tab
        self.ascii_pattern = re.compile(rb"[\x20-\x7E\t]{" + str(min_length).encode() + rb",}")
        # UTF-16LE: printable ASCII byte followed by 0x00
        self.utf16_pattern = re.compile(rb"(?:[\x20-\x7E\t]\x00){" + str(min_length).encode() + rb",}")

    def extract_from_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Extracts both ASCII and UTF-16LE strings with metadata.
        Returns a list of dicts:
            {
                "value": str,
                "encoding": "ASCII" | "UTF-16LE",
                "offset": int,
                "length": int,
                "entropy": float
            }
        """
        extracted: List[Dict[str, Any]] = []

        # 1. ASCII extraction
        for match in self.ascii_pattern.finditer(data):
            try:
                decoded = match.group().decode("ascii", errors="ignore").strip()
                if len(decoded) >= self.min_length:
                    extracted.append({
                        "value": decoded,
                        "encoding": "ASCII",
                        "offset": match.start(),
                        "length": len(decoded),
                        "entropy": calculate_string_entropy(decoded),
                    })
            except Exception:
                continue

        # 2. UTF-16LE (Wide string) extraction
        for match in self.utf16_pattern.finditer(data):
            try:
                decoded = match.group().decode("utf-16-le", errors="ignore").strip()
                if len(decoded) >= self.min_length:
                    extracted.append({
                        "value": decoded,
                        "encoding": "UTF-16LE",
                        "offset": match.start(),
                        "length": len(decoded),
                        "entropy": calculate_string_entropy(decoded),
                    })
            except Exception:
                continue

        # Sort strings by offset in binary
        extracted.sort(key=lambda s: s["offset"])
        return extracted

    def extract_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Reads file and returns all extracted strings."""
        with open(file_path, "rb") as f:
            data = f.read()
        return self.extract_from_bytes(data)
