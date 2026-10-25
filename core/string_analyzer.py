"""
String Analyzer & Weighted Scoring Engine.
Categorizes strings based on security indicators:
- Links (Instant Suspicious)
- Directory Paths (High Suspicious)
- Dangerous API References (Weighted by threat severity)
- Registry & Persistence Keys
- Obfuscated / High Entropy / Encoded Payloads
"""

import re
from typing import List, Dict, Any, Tuple


class StringAnalyzer:
    """Evaluates extracted strings using weighted heuristic rules and security criteria."""

    def __init__(self):
        # 1. URL and Network Indicators (Instant Suspicious - Weight: 35-45)
        self.url_pattern = re.compile(
            r"(?:https?|ftp|tcp|udp)://(?:[a-zA-Z0-9_\-\.]+(?::\d+)?(?:/[^\s]*)?)|"
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d{1,5})?\b|"
            r"[a-zA-Z0-9_\-\.]+\.(?:xyz|top|ru|cc|to|onion|bit)\b",
            re.IGNORECASE,
        )

        # 2. Directory and Filesystem Paths (High Suspicious - Weight: 25-30)
        self.path_pattern = re.compile(
            r"(?:[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*)|"
            r"(?:\\\\(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]*)|"
            r"(?:%(?:TEMP|APPDATA|LOCALAPPDATA|SYSTEMROOT|WINDIR|USERPROFILE)%\\[^\s]+)|"
            r"(?:(?:/etc/|/tmp/|/var/tmp/|/dev/shm/)[^\s]+)",
            re.IGNORECASE,
        )

        # 3. Registry & Persistence keys (Weight: 25-30)
        self.registry_pattern = re.compile(
            r"(?:HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKCU|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\"
            r"(?:Run|RunOnce|Policies|Explorer|App Paths)",
            re.IGNORECASE,
        )

        # 4. Command execution / Shell indicators (Weight: 30-35)
        self.cmd_pattern = re.compile(
            r"\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|"
            r"certutil(?:\.exe)?|bitsadmin(?:\.exe)?|vssadmin(?:\.exe)?|schtasks(?:\.exe)?|"
            r"regsvr32(?:\.exe)?|rundll32(?:\.exe)?|mshta(?:\.exe)?)\b",
            re.IGNORECASE,
        )

        # 5. Base64 encoded payload pattern (>= 32 chars)
        self.base64_pattern = re.compile(r"^[A-Za-z0-9+/]{32,}={0,2}$")

        # 6. Sensitive Windows APIs weighted by severity
        # Tier 1 (Critical - Injection, Memory Manipulation, Process Tampering): 35 pts
        self.api_tier1_injection = {
            "VirtualAllocEx": "Process memory allocation (often used for shellcode injection)",
            "WriteProcessMemory": "Cross-process memory writing (code injection)",
            "CreateRemoteThread": "Spawning execution thread in remote process",
            "QueueUserAPC": "Asynchronous procedure call injection",
            "NtMapViewOfSection": "Section mapping injection (process hollowing/doppelganging)",
            "NtUnmapViewOfSection": "Unmapping original executable section (process hollowing)",
            "SetThreadContext": "Modifying thread registers (process hollowing / hijacking)",
            "RtlCreateUserThread": "Undocumented thread creation in remote process",
        }

        # Tier 2 (High - Evasion, Persistence, Credential Access, Keylogging): 25-30 pts
        self.api_tier2_evasion_cred = {
            "IsDebuggerPresent": "Anti-analysis / debugger detection check",
            "CheckRemoteDebuggerPresent": "Remote debugger detection check",
            "NtQueryInformationProcess": "Querying process debug ports / anti-debug inspection",
            "OutputDebugStringA": "Anti-debugging trick (GetLastError manipulation)",
            "SetWindowsHookEx": "Global API / Keylogger hooking",
            "GetAsyncKeyState": "Keyboard state polling (keylogger indicator)",
            "GetKeyState": "Keystroke monitoring",
            "MiniDumpWriteDump": "Memory dumping (often targeted at LSASS for credential theft)",
            "OpenProcess": "Accessing handle to arbitrary target process",
            "AdjustTokenPrivileges": "Escalating security tokens (e.g. SeDebugPrivilege)",
            "LookupPrivilegeValue": "Privilege inspection for elevation",
            "RegSetValueEx": "Modifying registry value (persistence mechanism)",
            "RegCreateKeyEx": "Creating registry key (persistence mechanism)",
        }

        # Tier 3 (Medium - Network, Exfil, Process Launch): 20 pts
        self.api_tier3_network_exec = {
            "URLDownloadToFile": "Direct HTTP download to disk payload",
            "InternetOpenUrl": "Opening remote connection for payload fetch / C2 beacon",
            "InternetReadFile": "Reading remote response stream",
            "HttpSendRequest": "Sending HTTP beacon / exfiltration payload",
            "HttpOpenRequest": "Configuring C2 HTTP beacon",
            "WSAStartup": "Winsock network stack initialization",
            "socket": "Direct socket communication",
            "connect": "Opening direct socket outbound connection",
            "ShellExecute": "External binary or script execution",
            "CreateProcess": "Spawning new child process",
            "WinExec": "Legacy command execution API",
        }

        # Known noise filter (Standard CRT, C++ runtime, benign symbols)
        self.noise_strings = {
            "bad allocation", "std::exception", "vector<T> too long",
            "string too long", "CorExitProcess", "mscoree.dll",
            "GetProcessHeap", "HeapAlloc", "HeapFree", "GetModuleHandleA",
            "GetModuleHandleW", "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
            "ExitProcess", "GetLastError", "SetLastError", "KERNEL32.dll",
            "USER32.dll", "ADVAPI32.dll", "MSVCRT.dll", "ntdll.dll"
        }

    def evaluate_string(self, entry: Dict[str, Any]) -> Tuple[int, List[str], str]:
        """
        Evaluates a single string entry and returns:
        (total_weight, list_of_reasons, primary_category)
        """
        val = entry["value"].strip()
        entropy = entry.get("entropy", 0.0)
        weight = 0
        reasons = []
        category = "Benign/Informational"

        if val in self.noise_strings or len(val) < 4:
            return 0, [], "Noise"

        # Check for URLs / IPs (Instant Suspicious)
        url_match = self.url_pattern.search(val)
        if url_match:
            weight += 40
            reasons.append(f"Network indicator / URL / IP: '{url_match.group(0)}'")
            category = "Network / C2 Link"

        # Check for Directory Paths (High Suspicious)
        path_match = self.path_pattern.search(val)
        if path_match:
            # Differentiate system/sensitive paths
            matched_path = path_match.group(0)
            weight += 25
            if any(k in matched_path.lower() for k in ["system32", "syswow64", "temp", "appdata", "startup"]):
                weight += 10
                reasons.append(f"Sensitive OS directory path: '{matched_path}'")
            else:
                reasons.append(f"Filesystem path reference: '{matched_path}'")
            if category == "Benign/Informational":
                category = "Filesystem Path"

        # Check for Registry / Persistence Keys
        reg_match = self.registry_pattern.search(val)
        if reg_match:
            weight += 30
            reasons.append(f"Windows Autostart / Run Persistence Registry key: '{reg_match.group(0)}'")
            category = "Persistence / Registry"

        # Check for Command Shell execution tools
        cmd_match = self.cmd_pattern.search(val)
        if cmd_match:
            weight += 30
            reasons.append(f"System shell / LOLBin execution binary: '{cmd_match.group(0)}'")
            if category == "Benign/Informational":
                category = "Execution / Shell"

        # Check for Sensitive APIs (Tier 1: Injection)
        for api, desc in self.api_tier1_injection.items():
            if api.lower() in val.lower():
                weight += 35
                reasons.append(f"Tier 1 (Critical) API: '{api}' ({desc})")
                category = "Process Injection API"
                break

        # Check for Sensitive APIs (Tier 2: Evasion/Credentials)
        for api, desc in self.api_tier2_evasion_cred.items():
            if api.lower() in val.lower():
                weight += 25
                reasons.append(f"Tier 2 (High) API: '{api}' ({desc})")
                if category == "Benign/Informational":
                    category = "Evasion / Credential API"
                break

        # Check for Sensitive APIs (Tier 3: Network/Execution)
        for api, desc in self.api_tier3_network_exec.items():
            if api.lower() in val.lower():
                weight += 20
                reasons.append(f"Tier 3 API: '{api}' ({desc})")
                if category == "Benign/Informational":
                    category = "Network / Execution API"
                break

        # Check for Base64 encoded payload / high entropy obfuscated text
        if self.base64_pattern.match(val):
            weight += 25
            reasons.append(f"Base64 encoded string payload (length={len(val)}, entropy={entropy})")
            if category == "Benign/Informational":
                category = "Encoded Payload"
        elif len(val) >= 20 and entropy > 4.6 and not re.search(r"\s", val):
            weight += 20
            reasons.append(f"High-entropy obfuscated / encrypted string candidate (entropy={entropy})")
            if category == "Benign/Informational":
                category = "Obfuscated / High Entropy"

        return weight, reasons, category

    def analyze_strings(self, raw_strings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes a list of extracted strings.
        Returns:
            - scored_strings: List of all suspicious strings with weight > 0 sorted by weight desc
            - categorized_ioc: Dict of extracted IOCs (urls, paths, apis, commands)
            - total_score: Aggregate risk score
            - stats: Total strings parsed, suspicious strings found
        """
        scored_strings: List[Dict[str, Any]] = []
        iocs: Dict[str, List[str]] = {
            "urls_and_ips": [],
            "paths": [],
            "sensitive_apis": [],
            "commands": [],
            "registry_keys": [],
            "obfuscated": [],
        }

        total_risk_score = 0

        for entry in raw_strings:
            weight, reasons, category = self.evaluate_string(entry)
            if weight > 0:
                total_risk_score += weight
                scored_entry = {
                    "value": entry["value"],
                    "encoding": entry["encoding"],
                    "offset": hex(entry["offset"]),
                    "entropy": entry["entropy"],
                    "weight": weight,
                    "category": category,
                    "reasons": reasons,
                }
                scored_strings.append(scored_entry)

                # Collect into IOC bins
                val = entry["value"]
                if category == "Network / C2 Link":
                    if val not in iocs["urls_and_ips"]:
                        iocs["urls_and_ips"].append(val)
                elif "API" in category:
                    if val not in iocs["sensitive_apis"]:
                        iocs["sensitive_apis"].append(val)
                elif "Path" in category:
                    if val not in iocs["paths"]:
                        iocs["paths"].append(val)
                elif "Execution" in category or "Shell" in category:
                    if val not in iocs["commands"]:
                        iocs["commands"].append(val)
                elif "Persistence" in category or "Registry" in category:
                    if val not in iocs["registry_keys"]:
                        iocs["registry_keys"].append(val)
                elif "Encoded" in category or "Obfuscated" in category:
                    if val not in iocs["obfuscated"]:
                        iocs["obfuscated"].append(val)

        # Sort suspicious strings by weight descending
        scored_strings.sort(key=lambda s: s["weight"], reverse=True)

        return {
            "total_risk_score": total_risk_score,
            "suspicious_count": len(scored_strings),
            "total_strings_count": len(raw_strings),
            "top_suspicious_strings": scored_strings,
            "iocs": iocs,
        }
