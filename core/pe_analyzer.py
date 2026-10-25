"""
PE (Portable Executable) Analyzer Module.
Extracts cryptographic hashes, parses PE headers, sections, and analyzes packing indicators
based on the discrepancy between VirtualSize and SizeOfRawData, as well as section entropy.
"""

import math
import hashlib
from typing import Dict, Any, List, Optional
import pefile


def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_hashes(file_bytes: bytes) -> Dict[str, str]:
    """Computes MD5, SHA1, and SHA256 hashes of the binary."""
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


class PEAnalyzer:
    """Analyzes Windows PE files for structural integrity, sections, and packing."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        with open(file_path, "rb") as f:
            self.file_bytes = f.read()
        self.hashes = calculate_hashes(self.file_bytes)
        self.pe: Optional[pefile.PE] = None
        self.is_valid_pe = False
        self._load_pe()

    def _load_pe(self):
        try:
            self.pe = pefile.PE(data=self.file_bytes)
            self.is_valid_pe = True
        except Exception:
            self.pe = None
            self.is_valid_pe = False

    def analyze_packing(self) -> Dict[str, Any]:
        """
        Detects whether the PE binary is packed.
        Heuristics:
        1. Large discrepancy between VirtualSize and SizeOfRawData:
           Packers allocate a large virtual memory space to unpack compressed data stored
           in a much smaller raw section (or raw size is 0).
        2. High section entropy (> 7.0 indicates compression or encryption).
        3. Known packer section names (e.g. UPX0, UPX1, .aspack, .vmp0).
        """
        if not self.is_valid_pe or not self.pe:
            return {
                "is_packed": False,
                "confidence": "N/A",
                "reason": "Not a valid Windows PE binary",
                "sections": [],
            }

        known_packer_sections = {
            "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".fsg", ".themida",
            ".vmp0", ".vmp1", "pec1", "pec2", ".nsp0", ".packer", "MEW", ".enigma"
        }

        suspicious_sections: List[Dict[str, Any]] = []
        is_packed = False
        confidence = "Low"
        reasons = []

        total_sections = len(self.pe.sections)
        high_entropy_sections = 0

        for section in self.pe.sections:
            try:
                name = section.Name.decode("latin-1", errors="ignore").strip("\x00")
            except Exception:
                name = "Unknown"

            vsize = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            sec_data = section.get_data()
            entropy = calculate_entropy(sec_data)

            # Check if section entropy is high (compressed/encrypted payload)
            is_high_entropy = entropy > 7.0
            if is_high_entropy:
                high_entropy_sections += 1

            # Discrepancy calculation:
            # If RawSize is 0 but VirtualSize > 0 (classic UPX0 / unpacking buffer)
            # Or if VirtualSize is significantly larger than RawSize
            size_delta = vsize - raw_size
            ratio = (vsize / raw_size) if raw_size > 0 else (999.0 if vsize > 0 else 1.0)
            
            is_discrepancy_suspicious = False
            discrepancy_note = ""

            if raw_size == 0 and vsize > 0x1000:
                is_discrepancy_suspicious = True
                discrepancy_note = f"Zero raw size with {vsize} bytes virtual allocation"
            elif raw_size > 0 and ratio >= 3.0 and size_delta > 0x2000:
                is_discrepancy_suspicious = True
                discrepancy_note = f"Virtual size ({vsize} bytes) is {ratio:.1f}x larger than raw size ({raw_size} bytes)"

            # Known packer section name match
            is_packer_name = any(sig.lower() in name.lower() for sig in known_packer_sections)

            sec_info = {
                "name": name,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "entropy": entropy,
                "size_delta": size_delta,
                "discrepancy_ratio": round(ratio, 2),
                "is_high_entropy": is_high_entropy,
                "is_discrepancy_suspicious": is_discrepancy_suspicious,
                "is_packer_name": is_packer_name,
                "note": discrepancy_note
            }
            suspicious_sections.append(sec_info)

            if is_packer_name:
                reasons.append(f"Known packer section signature detected: '{name}'")
            if is_discrepancy_suspicious:
                reasons.append(f"Section '{name}': {discrepancy_note}")

        if high_entropy_sections > 0:
            reasons.append(f"{high_entropy_sections}/{total_sections} section(s) have high entropy (>7.0), indicating compression/encryption.")

        # Determine overall packed status & confidence
        if any(s["is_packer_name"] for s in suspicious_sections):
            is_packed = True
            confidence = "High"
        elif any(s["is_discrepancy_suspicious"] for s in suspicious_sections) and high_entropy_sections > 0:
            is_packed = True
            confidence = "High"
        elif any(s["is_discrepancy_suspicious"] for s in suspicious_sections):
            is_packed = True
            confidence = "Medium"
        elif high_entropy_sections >= (total_sections / 2) and total_sections > 0:
            is_packed = True
            confidence = "Medium"

        return {
            "is_packed": is_packed,
            "confidence": confidence,
            "reasons": reasons if reasons else ["Standard section geometry and entropy observed"],
            "sections": suspicious_sections,
            "high_entropy_count": high_entropy_sections,
            "total_sections": total_sections,
        }

    def get_pe_summary(self) -> Dict[str, Any]:
        """Returns overall PE metadata and header insights."""
        packing_info = self.analyze_packing()
        arch = "Unknown"
        subsystem = "Unknown"
        timestamp = 0

        if self.is_valid_pe and self.pe:
            machine = getattr(self.pe.FILE_HEADER, "Machine", 0)
            if machine == 0x014c:
                arch = "x86 (32-bit)"
            elif machine == 0x8664:
                arch = "x64 (64-bit)"
            elif machine == 0xaa64:
                arch = "ARM64"
            else:
                arch = f"0x{machine:04x}"

            timestamp = getattr(self.pe.FILE_HEADER, "TimeDateStamp", 0)
            subsys_val = getattr(self.pe.OPTIONAL_HEADER, "Subsystem", 0)
            subsystems = {1: "Native", 2: "Windows GUI", 3: "Windows CUI (Console)"}
            subsystem = subsystems.get(subsys_val, f"Subsystem {subsys_val}")

        return {
            "file_path": self.file_path,
            "file_size": len(self.file_bytes),
            "is_valid_pe": self.is_valid_pe,
            "architecture": arch,
            "subsystem": subsystem,
            "timestamp": timestamp,
            "hashes": self.hashes,
            "packing": packing_info,
        }
