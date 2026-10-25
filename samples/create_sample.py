"""
Generates synthetic PE samples for testing static analysis rules and packing heuristics
without requiring live dangerous malware.
"""

import os
import struct


def build_minimal_pe(packed: bool = False) -> bytes:
    """
    Constructs a synthetically valid minimal PE32 executable binary buffer.
    If packed=True, simulates a packed section (VirtualSize >> RawSize, high entropy payload, UPX0 name).
    """
    # 1. DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew at offset 0x3C points to PE header (0x80)
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    # DOS Stub padding up to offset 0x80
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
    dos_padding = bytearray(0x80 - 64)
    dos_padding[:len(dos_stub)] = dos_stub

    # 2. PE Signature
    pe_sig = b"PE\x00\x00"

    # 3. COFF File Header (20 bytes)
    # Machine: 0x014c (x86), NumberOfSections: 2 or 3, TimeDateStamp: 0x60000000, SizeOfOptionalHeader: 0xE0, Characteristics: 0x0102
    num_sections = 2
    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,         # Machine (i386)
        num_sections,   # NumberOfSections
        0x67150000,     # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        0x00E0,         # SizeOfOptionalHeader
        0x0102          # Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)
    )

    # 4. Optional Header Standard + Windows Specific (224 bytes = 0xE0)
    opt_header = bytearray(0xE0)
    struct.pack_into("<H", opt_header, 0, 0x010B)         # Magic: PE32
    struct.pack_into("<I", opt_header, 16, 0x1000)        # AddressOfEntryPoint (RVA 0x1000)
    struct.pack_into("<I", opt_header, 28, 0x400000)      # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)        # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)         # FileAlignment
    struct.pack_into("<H", opt_header, 44, 4)             # MajorSubsystemVersion
    struct.pack_into("<I", opt_header, 56, 0x8000)        # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x400)         # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 3)             # Subsystem: Windows CUI (Console)
    struct.pack_into("<I", opt_header, 92, 16)            # NumberOfRvaAndSizes

    # 5. Section Headers (40 bytes each)
    # Section 1: Code / Payload (.text or UPX0)
    sec1_name = b"UPX0\x00\x00\x00\x00" if packed else b".text\x00\x00\x00"
    sec1_vsize = 0x5000 if packed else 0x1000
    sec1_rva = 0x1000
    sec1_rawsize = 0 if packed else 0x400  # Raw size 0 in packed stub
    sec1_rawptr = 0 if packed else 0x400
    sec1_chars = 0xE0000020  # CODE | EXECUTE | READ | WRITE

    sec1_header = struct.pack(
        "<8sIIIIIIHHI",
        sec1_name,
        sec1_vsize,
        sec1_rva,
        sec1_rawsize,
        sec1_rawptr,
        0, 0, 0, 0,
        sec1_chars
    )

    # Section 2: Data / Strings (.rdata or UPX1)
    sec2_name = b"UPX1\x00\x00\x00\x00" if packed else b".rdata\x00\x00"
    sec2_vsize = 0x2000
    sec2_rva = 0x6000 if packed else 0x2000
    sec2_rawsize = 0x1000
    sec2_rawptr = 0x400 if packed else 0x800
    sec2_chars = 0xC0000040  # INITIALIZED_DATA | READ | WRITE

    sec2_header = struct.pack(
        "<8sIIIIIIHHI",
        sec2_name,
        sec2_vsize,
        sec2_rva,
        sec2_rawsize,
        sec2_rawptr,
        0, 0, 0, 0,
        sec2_chars
    )

    # Header block padded to 0x400 (FileAlignment)
    headers = dos_header + dos_padding + pe_sig + coff_header + opt_header + sec1_header + sec2_header
    headers = headers.ljust(0x400, b"\x00")

    # 6. Payload data containing realistic test strings (ASCII + UTF-16LE)
    # ASCII strings
    ascii_payload = (
        b"VirtualAllocEx\x00"
        b"WriteProcessMemory\x00"
        b"CreateRemoteThread\x00"
        b"IsDebuggerPresent\x00"
        b"URLDownloadToFileA\x00"
        b"http://malicious-c2-domain.xyz/payload.exe\x00"
        b"http://185.220.101.5:443/beacon\x00"
        b"C:\\Windows\\System32\\cmd.exe\x00"
        b"%TEMP%\\dropper_stage2.exe\x00"
        b"powershell.exe -ExecutionPolicy Bypass -enc \x00"
        b"aHR0cHM6Ly9hdHRhY2tlci5jb20vc2hlbGxjb2RlLmJpbg==\x00"
        b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\x00"
    )

    # Ensure 2-byte alignment for UTF-16LE strings (standard Windows PE convention)
    if len(ascii_payload) % 2 != 0:
        ascii_payload += b"\x00"

    # UTF-16LE wide strings
    utf16_payload = (
        "MiniDumpWriteDump\x00".encode("utf-16-le") +
        "AdjustTokenPrivileges\x00".encode("utf-16-le") +
        "https://pastebin.com/raw/d34db33f\x00".encode("utf-16-le") +
        "C:\\Users\\Public\\AppData\\Roaming\\stealer.dll\x00".encode("utf-16-le")
    )

    section_data = (ascii_payload + utf16_payload).ljust(0x1000, b"\x90")

    return headers + section_data


def generate_samples(output_dir: str = "samples"):
    os.makedirs(output_dir, exist_ok=True)

    unpacked_path = os.path.join(output_dir, "sample_unpacked.exe")
    packed_path = os.path.join(output_dir, "sample_packed_sim.exe")

    with open(unpacked_path, "wb") as f:
        f.write(build_minimal_pe(packed=False))

    with open(packed_path, "wb") as f:
        f.write(build_minimal_pe(packed=True))

    print(f"[+] Created synthetic test samples in '{output_dir}':")
    print(f"    - {unpacked_path}")
    print(f"    - {packed_path}")


if __name__ == "__main__":
    generate_samples()
