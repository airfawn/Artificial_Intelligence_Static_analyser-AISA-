# Automating Static Analysis

An automated static analysis and binary triage engine built for security analysts, incident responders, and malware researchers. It inspects Windows Portable Executable (PE) binaries to detect packing, extracts both ASCII and UTF-16LE strings, evaluates threats using a weighted security model, and extracts key Indicators of Compromise (IOCs).

---

## Architecture Overview

```
Automating_Static_Analysis/
├── core/
│   ├── pe_analyzer.py        # Hashes (MD5, SHA1, SHA256), PE header parsing, section geometry & packing heuristics
│   ├── string_extractor.py   # Native dual-encoding (ASCII & UTF-16LE) extractor with byte offsets & entropy
│   ├── string_analyzer.py    # Weighted scoring engine & IOC classifier (URLs, paths, sensitive APIs, registry, shell)
│   └── ml_model.py           # Feature extractor, classifier, and Reinforcement Learning feedback loop for obfuscation
├── cli/
│   └── visualizer.py         # Rich terminal tables, color-coded packing alerts, string scorecards, and IOC panels
├── samples/
│   └── create_sample.py      # Synthetic PE generator for testing without requiring live malware
├── tests/
│   └── test_analyzer.py      # Automated unit tests
├── main.py                   # Main CLI entrypoint
└── requirements.txt
```

---

## Core Features Implemented

### 1. PE Header & Packing Detection (`core/pe_analyzer.py`)
- **VirtualSize vs. SizeOfRawData Anomaly:** Flags sections where `VirtualSize >> SizeOfRawData` or where `SizeOfRawData == 0` with high virtual allocation (classic unpacking buffer indicator).
- **Shannon Entropy Analysis:** Computes section entropy ($0.0 - 8.0$). Sections with entropy $> 7.0$ indicate compressed or encrypted payloads.
- **Packer Signatures:** Detects standard packer stub section names (`UPX0`, `UPX1`, `.aspack`, `.themida`, `.vmp0`).
- **Cryptographic Hashes:** Calculates MD5, SHA-1, and SHA-256 for threat-intel lookups.

### 2. Native Dual-Encoding String Extractor (`core/string_extractor.py`)
- **Cross-Platform:** Pure Python binary scanning without external OS dependencies (`strings`).
- **Encodings Supported:**
  - Standard Printable ASCII (`0x20` to `0x7E`)
  - Windows UTF-16LE Wide Strings (common in `.rdata` and resource sections)
- **Metadata Tagging:** Captures byte offset (hex), string length, encoding type, and per-string Shannon entropy.

### 3. Weighted Threat Scoring Engine (`core/string_analyzer.py`)
Categorizes and scores strings according to security risk:
- **Network & C2 Links (Weight: 40 - Instant Suspicious):** Detects URLs, raw IPv4/IPv6 with ports, paste sites, and suspicious TLDs (`.xyz`, `.onion`, `.top`).
- **Filesystem Paths (Weight: 25-35 - High Suspicious):** Detects system paths (`C:\Windows\System32\...`), environment variables (`%TEMP%`, `%APPDATA%`), and autostart paths.
- **Sensitive Windows APIs (Weight: 20-35):**
  - *Tier 1 (Critical - Injection & Hollowing):* `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `NtMapViewOfSection`.
  - *Tier 2 (High - Evasion & Credentials):* `IsDebuggerPresent`, `NtQueryInformationProcess`, `SetWindowsHookEx`, `MiniDumpWriteDump`, `AdjustTokenPrivileges`.
  - *Tier 3 (Medium - Network & Execution):* `URLDownloadToFile`, `HttpSendRequest`, `CreateProcess`, `ShellExecute`.
- **Registry Persistence (Weight: 30):** Autostart registry keys (`...CurrentVersion\Run`).
- **Obfuscated Payloads (Weight: 20-25):** Base64 encoded payload blocks and high-entropy alphanumeric strings.

### 4. Machine Learning & Reinforcement Learning Harness (`core/ml_model.py`)
- **Feature Extraction:** Character ratios (digits, uppercase, hex, punctuation), Shannon entropy, structural markers (URLs, file extensions, base64 charset).
- **RL Feedback Loop:** Reward penalties and gradients for adjusting weights against obfuscated strings while heavily penalizing false positives on benign compiler runtimes.

---

## Getting Started

### 1. Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate Synthetic Test Samples
```bash
python samples/create_sample.py
```
This generates:
- `samples/sample_unpacked.exe`
- `samples/sample_packed_sim.exe` (with simulated UPX packing geometry)

### 3. Run Analysis
```bash
# Terminal visual output
python main.py samples/sample_packed_sim.exe

# Export structured JSON report for SOC / SIEM
python main.py samples/sample_packed_sim.exe --json report.json
```

### 4. Run Unit Tests
```bash
python -m unittest discover tests
```

---

## Roadmap

- [x] **Function 1:** PE Header packing detection + Dual-encoding string extractor + Weighted scoring + IOC extraction.
- [ ] **Function 2:** Import Address Table (IAT) & Export Table parsing with API call graph correlation.
- [ ] **Function 3:** Threat Intel Reputation lookups (VirusTotal API, OTX) for SHA256 / C2 IPs.
- [ ] **Function 4:** AI LLM Summary Agent: Generates human-readable malware family, role, and MITRE ATT&CK mapping reports.
