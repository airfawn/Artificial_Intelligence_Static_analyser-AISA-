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


def build_dropper_pe() -> bytes:
    """
    Builds a synthetic PE that:
    1. Has URLDownloadToFileA + CreateProcessA in its Import Directory
       (download-and-execute API pair — network dropper signal).
    2. Contains a second complete MZ/PE header embedded in its .data section
       (embedded PE file-dropper signal).
    The outer PE is a valid minimal x86 executable that pefile can parse.
    """
    # ── Inner PE (the "payload" that will be embedded) ─────────────────────
    # We reuse the minimal unpacked PE bytes as the embedded payload
    inner_pe = build_minimal_pe(packed=False)

    # ── Outer PE construction ────────────────────────────────────────────────
    # DOS Header
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00"
    dos_padding = bytearray(0x80 - 64)
    dos_padding[:len(dos_stub)] = dos_stub

    pe_sig = b"PE\x00\x00"

    # COFF — 3 sections: .text, .rdata (imports), .data (holds embedded PE)
    num_sections = 3
    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C, num_sections, 0x67150001, 0, 0, 0x00E0, 0x0102
    )

    opt_header = bytearray(0xE0)
    struct.pack_into("<H", opt_header, 0, 0x010B)
    struct.pack_into("<I", opt_header, 16, 0x1000)   # EntryPoint RVA
    struct.pack_into("<I", opt_header, 28, 0x400000) # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)   # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)    # FileAlignment
    struct.pack_into("<H", opt_header, 44, 4)
    struct.pack_into("<I", opt_header, 56, 0xC000)   # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x400)    # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 3)        # Subsystem Console
    struct.pack_into("<I", opt_header, 92, 16)       # NumberOfRvaAndSizes

    # Import directory RVA will be in .rdata at RVA 0x2000 (file offset 0x800)
    struct.pack_into("<I", opt_header, 96 + 1 * 8, 0x2000)   # Import Table RVA
    struct.pack_into("<I", opt_header, 96 + 1 * 8 + 4, 0x100) # Import Table Size

    # ── Section headers ──────────────────────────────────────────────────────
    def make_section(name: bytes, vsize: int, rva: int, rawsize: int, rawptr: int, chars: int) -> bytes:
        name_padded = name.ljust(8, b"\x00")[:8]
        return struct.pack("<8sIIIIIIHHI", name_padded, vsize, rva, rawsize, rawptr, 0, 0, 0, 0, chars)

    sec_text  = make_section(b".text",  0x1000, 0x1000, 0x200, 0x400, 0xE0000020)
    sec_rdata = make_section(b".rdata", 0x1000, 0x2000, 0x400, 0x600, 0xC0000040)
    # .data section holds the embedded PE — raw size matches inner PE size
    embedded_raw_size = (len(inner_pe) + 0x1FF) & ~0x1FF  # round up to 0x200
    sec_data  = make_section(b".data",  max(0x2000, len(inner_pe)), 0x3000,
                             embedded_raw_size, 0xA00, 0xC0000040)

    # Headers block — padded to 0x400 (FileAlignment)
    headers = (dos_header + dos_padding + pe_sig + coff_header +
               opt_header + sec_text + sec_rdata + sec_data)
    headers = bytes(headers).ljust(0x400, b"\x00")

    # ── .text section (0x200 bytes of NOPs) ─────────────────────────────────
    text_data = b"\x90" * 0x200

    # ── .rdata section — minimal Import Directory with URLDownloadToFileA + CreateProcessA ──
    # Import Directory layout (simplified, enough for pefile to parse):
    #   Two IMAGE_IMPORT_DESCRIPTOR entries + null terminator
    #   String table: DLL names, function name hints

    # String table offsets relative to start of .rdata raw data
    # We put strings first, then the descriptors
    RDATA_RVA = 0x2000
    RDATA_RAWSTART = 0x600

    # String layout (all at start of .rdata raw data, offsets within raw data):
    str_table = bytearray()

    # [0x00] DLL name: "URLMON.dll\0"
    OFF_URLMON       = len(str_table); str_table += b"URLMON.dll\x00"
    # [0x0B] DLL name: "KERNEL32.dll\0"
    OFF_KERNEL32     = len(str_table); str_table += b"KERNEL32.dll\x00"
    # [0x18] Hint+name: URLDownloadToFileA
    OFF_HINT_URLDL   = len(str_table); str_table += b"\x00\x00URLDownloadToFileA\x00"
    # Hint+name: CreateProcessA
    OFF_HINT_CPROC   = len(str_table); str_table += b"\x00\x00CreateProcessA\x00"

    # Align str_table to 4 bytes
    while len(str_table) % 4:
        str_table += b"\x00"

    # Import Lookup Tables (ILTs) — each is an array of 32-bit RVAs to hint/name entries
    # Followed by null terminator (4 zero bytes)
    OFF_ILT_URLMON   = len(str_table)
    hint_urlmon_rva  = RDATA_RVA + OFF_HINT_URLDL
    struct.pack_into if False else None  # linter hint
    str_table += struct.pack("<II", hint_urlmon_rva, 0)  # ILT for URLMON: one entry + null

    OFF_ILT_KERNEL32 = len(str_table)
    hint_cproc_rva   = RDATA_RVA + OFF_HINT_CPROC
    str_table += struct.pack("<II", hint_cproc_rva, 0)  # ILT for KERNEL32: one entry + null

    # IMAGE_IMPORT_DESCRIPTOR for URLMON (20 bytes each)
    OFF_IID_URLMON   = len(str_table)
    str_table += struct.pack(
        "<IIIII",
        RDATA_RVA + OFF_ILT_URLMON,    # OriginalFirstThunk (ILT RVA)
        0,                             # TimeDateStamp
        0,                             # ForwarderChain
        RDATA_RVA + OFF_URLMON,        # Name RVA
        RDATA_RVA + OFF_ILT_URLMON,    # FirstThunk (IAT RVA)
    )
    # IMAGE_IMPORT_DESCRIPTOR for KERNEL32
    str_table += struct.pack(
        "<IIIII",
        RDATA_RVA + OFF_ILT_KERNEL32,
        0, 0,
        RDATA_RVA + OFF_KERNEL32,
        RDATA_RVA + OFF_ILT_KERNEL32,
    )
    # Null terminator descriptor
    str_table += b"\x00" * 20

    # Pad .rdata to 0x400 bytes
    rdata_data = bytes(str_table).ljust(0x400, b"\x00")

    # Also embed readable ASCII strings for the string extractor
    dropper_strings = (
        b"URLDownloadToFileA\x00"
        b"CreateProcessA\x00"
        b"http://malicious-dropper.xyz/payload.exe\x00"
        b"%TEMP%\\dropped_payload.exe\x00"
        b"URLMON.dll\x00"
        b"KERNEL32.dll\x00"
    )
    rdata_data = (dropper_strings + rdata_data[len(dropper_strings):]).ljust(0x400, b"\x00")

    # ── .data section — the embedded inner PE ───────────────────────────────
    # Prepend a small marker and then the inner PE raw bytes
    marker = b"[DROPPER_PAYLOAD_START]"
    data_section = (marker + inner_pe).ljust(embedded_raw_size, b"\x00")

    # ── Assemble final binary ────────────────────────────────────────────────
    # Padding between sections to reach correct file offsets
    # .text  at 0x400, .rdata at 0x600, .data at 0xA00
    pad_to_text  = b"\x00" * (0x400 - len(headers))   # already 0x400
    pad_to_rdata = b"\x00" * (0x600 - 0x400 - len(text_data))
    pad_to_data  = b"\x00" * (0xA00 - 0x600 - len(rdata_data))

    return (headers + text_data + pad_to_rdata +
            rdata_data + pad_to_data + data_section)


def generate_samples(output_dir: str = "samples"):
    os.makedirs(output_dir, exist_ok=True)

    unpacked_path = os.path.join(output_dir, "sample_unpacked.exe")
    packed_path   = os.path.join(output_dir, "sample_packed_sim.exe")
    dropper_path  = os.path.join(output_dir, "sample_dropper_sim.exe")

    with open(unpacked_path, "wb") as f:
        f.write(build_minimal_pe(packed=False))

    with open(packed_path, "wb") as f:
        f.write(build_minimal_pe(packed=True))

    with open(dropper_path, "wb") as f:
        f.write(build_dropper_pe())

    print(f"[+] Created synthetic test samples in '{output_dir}':")
    print(f"    - {unpacked_path}")
    print(f"    - {packed_path}")
    print(f"    - {dropper_path}  (embedded PE dropper simulation)")


if __name__ == "__main__":
    generate_samples()

