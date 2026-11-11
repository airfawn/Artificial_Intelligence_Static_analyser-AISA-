"""
PE (Portable Executable) Analyzer Module.
Extracts cryptographic hashes, parses PE headers, sections, and analyzes packing indicators
based on the discrepancy between VirtualSize and SizeOfRawData, as well as section entropy.

Dropper Detection:
- Embedded PE scan: scans the raw binary bytes for nested MZ/PE headers, which indicates
  a file-dropper that carries another executable as payload.
- Download-and-Execute correlation: detects co-occurrence of download APIs with process
  launch APIs, a key indicator of a network dropper / stager.
"""

import math
import hashlib
import struct
from typing import Dict, Any, List, Optional
import pefile

# ---------------------------------------------------------------------------
# Download APIs that pull remote payloads to disk or into memory
# ---------------------------------------------------------------------------
_DOWNLOAD_APIS = {
    "URLDownloadToFile",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenUrl",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "InternetReadFile",
    "HttpSendRequest",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "HttpOpenRequest",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReadData",
}

# ---------------------------------------------------------------------------
# Execution APIs that launch a downloaded payload
# ---------------------------------------------------------------------------
_EXECUTION_APIS = {
    "CreateProcess",
    "CreateProcessA",
    "CreateProcessW",
    "ShellExecute",
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteEx",
    "WinExec",
    "LoadLibrary",
    "LoadLibraryA",
    "LoadLibraryW",
    "CreateThread",
    "CreateRemoteThread",
    "NtCreateThreadEx",
}


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
                "reasons": ["Not a valid Windows PE binary"],
                "sections": [],
            }

        known_packer_sections = {
            "UPX0", "UPX1", "UPX2", ".upx", ".aspack", ".adata", ".fsg", ".themida",
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
                note = " (common data section; not sufficient alone)" if name.lower() in {".data", ".bss"} else ""
                reasons.append(f"Section '{name}': {discrepancy_note}{note}")

        if high_entropy_sections > 0:
            reasons.append(f"{high_entropy_sections}/{total_sections} section(s) have high entropy (>7.0), indicating compression/encryption.")

        # Determine overall packed status & confidence
        suspicious_geometry = any(
            s["is_discrepancy_suspicious"] and s["name"].lower() not in {".data", ".bss"}
            for s in suspicious_sections
        )
        if any(s["is_packer_name"] for s in suspicious_sections):
            is_packed = True
            confidence = "High"
        elif suspicious_geometry and high_entropy_sections > 0:
            is_packed = True
            confidence = "High"
        elif suspicious_geometry:
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

    # ------------------------------------------------------------------
    # DROPPER DETECTION
    # ------------------------------------------------------------------

    def detect_embedded_pe(self) -> List[Dict[str, Any]]:
        """
        Scans raw file bytes for embedded PE files (MZ + PE signature).

        How it works:
        1. Search the entire byte stream for every occurrence of b'MZ'.
        2. For each MZ hit (excluding offset 0 which is the outer PE itself),
           read the 4-byte little-endian DWORD at offset +0x3C — this is
           `e_lfanew`, the pointer to the PE signature.
        3. Verify that the bytes at that pointed-to offset spell 'PE\\x00\\x00'.
        4. A confirmed inner MZ+PE header means a whole executable is
           embedded inside this file — a classic dropper payload carrier.

        Returns a list of dicts, one per confirmed embedded PE:
            {
                "offset":     int   — byte offset of the inner MZ header
                "offset_hex": str   — same as hex string
                "inner_hashes": dict — MD5 / SHA256 of the embedded blob
                                       (from MZ to end-of-file; exact bounds
                                        require unpacking, so we use a window)
            }
        """
        embedded: List[Dict[str, Any]] = []
        data = self.file_bytes
        search_start = 2  # skip the outermost MZ at offset 0

        idx = data.find(b"MZ", search_start)
        while idx != -1:
            # Bounds-check: need at least 0x40 bytes from this MZ for a valid DOS header
            if idx + 0x40 <= len(data):
                try:
                    e_lfanew = struct.unpack_from("<I", data, idx + 0x3C)[0]
                    pe_sig_offset = idx + e_lfanew
                    # Sanity: e_lfanew must be reasonable (< 1 MB from MZ)
                    if (0x40 <= e_lfanew < 0x100000) and (pe_sig_offset + 4 <= len(data)):
                        if data[pe_sig_offset: pe_sig_offset + 4] == b"PE\x00\x00":
                            # Valid inner PE confirmed — capture a blob for hashing
                            blob = data[idx: idx + min(0x200000, len(data) - idx)]
                            inner_hashes = {
                                "md5": hashlib.md5(blob).hexdigest(),
                                "sha256": hashlib.sha256(blob).hexdigest(),
                            }
                            embedded.append({
                                "offset": idx,
                                "offset_hex": hex(idx),
                                "inner_hashes": inner_hashes,
                            })
                except Exception:
                    pass
            idx = data.find(b"MZ", idx + 1)

        return embedded

    def analyze_dropper(self) -> Dict[str, Any]:
        """
        Dropper Analysis — combines two independent signals:

        Signal 1 — Embedded PE (file-based dropper / packer with real payload):
            Weight contribution: +60 per embedded PE (High Confidence)
            Reason: Carrying another executable inside the binary body is
            the defining characteristic of a file-dropper. Legitimate software
            almost never embeds a second PE in its raw bytes.

        Signal 2 — Download-and-Execute API correlation (network dropper / stager):
            Detects whether the Import Directory references BOTH a payload-
            download API (URLDownloadToFile, WinHttpSendRequest, etc.) AND
            a process-launch API (CreateProcess, ShellExecute, WinExec, etc.).
            That specific combination — fetch remote binary → run it — is the
            canonical network stager / dropper pattern.
            Weight contribution: +50 (High Confidence)

        Returns:
            {
                "is_dropper":       bool
                "dropper_weight":   int    — contributed to overall risk score
                "confidence":       str    — "High" / "Medium" / "Low" / "None"
                "signals":          list   — human-readable reasons
                "embedded_pes":     list   — confirmed embedded PE descriptors
                "download_apis_found":  list
                "execution_apis_found": list
            }
        """
        dropper_weight = 0
        signals: List[str] = []
        embedded_pes: List[Dict[str, Any]] = []
        download_found: List[str] = []
        execution_found: List[str] = []

        # ── Signal 1: Embedded PE scan ──────────────────────────────────────
        embedded_pes = self.detect_embedded_pe()
        if embedded_pes:
            count = len(embedded_pes)
            dropper_weight += 60 * count
            offsets = ", ".join(e["offset_hex"] for e in embedded_pes)
            signals.append(
                f"Embedded PE file{'s' if count > 1 else ''} detected ({count} found at offset{'s' if count > 1 else ''}: {offsets}) — "
                f"file-dropper carrier pattern confirmed"
            )

        # ── Signal 2: Download + Execute API co-occurrence in imports ────────
        if self.is_valid_pe and self.pe:
            try:
                for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
                    for imp in entry.imports:
                        if not imp.name:
                            continue
                        name = imp.name.decode("ascii", errors="ignore")
                        # Exact or prefix match (handles A/W suffix variants)
                        for api in _DOWNLOAD_APIS:
                            if name == api or name.startswith(api.rstrip("AW")):
                                if name not in download_found:
                                    download_found.append(name)
                        for api in _EXECUTION_APIS:
                            if name == api or name.startswith(api.rstrip("AW")):
                                if name not in execution_found:
                                    execution_found.append(name)
            except Exception:
                pass

        if download_found and execution_found:
            dropper_weight += 50
            signals.append(
                f"Download-and-Execute API pair detected — "
                f"Download: {download_found[:3]} + Execute: {execution_found[:3]}"
            )
        elif download_found and not execution_found:
            # Only download APIs — possible downloader / stager (lighter weight)
            dropper_weight += 25
            signals.append(
                f"Downloader-only API pattern — download APIs present ({download_found[:3]}) "
                f"but no direct execution API in IAT (may use dynamic LoadLibrary)"
            )

        # ── Confidence level ─────────────────────────────────────────────────
        is_dropper = dropper_weight > 0
        if dropper_weight >= 80:
            confidence = "High"
        elif dropper_weight >= 40:
            confidence = "Medium"
        elif dropper_weight > 0:
            confidence = "Low"
        else:
            confidence = "None"

        return {
            "is_dropper": is_dropper,
            "dropper_weight": dropper_weight,
            "confidence": confidence,
            "signals": signals if signals else ["No dropper indicators detected"],
            "embedded_pes": embedded_pes,
            "download_apis_found": download_found,
            "execution_apis_found": execution_found,
        }

    def get_pe_summary(self, include_dropper: bool = True) -> Dict[str, Any]:
        """Returns overall PE metadata and header insights, including dropper analysis."""
        packing_info = self.analyze_packing()
        dropper_info = self.analyze_dropper() if include_dropper else None
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

        summary = {
            "file_path": self.file_path,
            "file_size": len(self.file_bytes),
            "is_valid_pe": self.is_valid_pe,
            "architecture": arch,
            "subsystem": subsystem,
            "timestamp": timestamp,
            "hashes": self.hashes,
            "packing": packing_info,
        }
        if include_dropper:
            summary["dropper"] = dropper_info
        return summary
