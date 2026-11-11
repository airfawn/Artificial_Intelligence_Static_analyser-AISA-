"""Identify candidate indicators in extracted strings without assigning risk."""

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit


URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_.-])"
)
PATH_PATTERN = re.compile(
    r"""(?:"(?:[A-Za-z]:\\|\\\\|%[A-Za-z_][A-Za-z0-9_]*%\\)[^"\r\n]+"|"""
    r"""(?:[A-Za-z]:\\|\\\\|%[A-Za-z_][A-Za-z0-9_]*%\\)[^\s"'<>|]+|"""
    r"""(?<![A-Za-z0-9:/.])/(?:etc|tmp|var|usr|home|opt|dev)/[^\s"'<>|]+)""",
    re.IGNORECASE,
)
COMMAND_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|"
    r"wscript(?:\.exe)?|cscript(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
    r"vssadmin(?:\.exe)?|schtasks(?:\.exe)?|regsvr32(?:\.exe)?|rundll32(?:\.exe)?|"
    r"mshta(?:\.exe)?)(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
NON_DOMAIN_SUFFIXES = {
    "bat", "cfg", "conf", "config", "dat", "db", "dll", "doc", "docx", "ds", "exe",
    "fsi", "ico", "ini", "js", "jsd", "json", "log", "pdf", "plist", "ps1",
    "qfp", "scr", "smf", "sqlite", "sqlite3", "sys", "tmp", "txt", "vbs",
    "xml", "yaml", "yml",
}


def categorize_strings(strings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Return candidate matches with their original string index and character span."""
    categories: Dict[str, List[Dict[str, Any]]] = {
        "domains": [], "file_paths": [], "urls": [], "commands": [],
    }

    def add(category: str, value: str, index: int, start: int, end: int) -> None:
        categories[category].append({
            "value": value,
            "string_index": index,
            "string_offset": strings[index]["offset"],
            "encoding": strings[index]["encoding"],
            "match_start": start,
            "match_end": end,
        })

    for index, entry in enumerate(strings):
        text = entry["value"]
        url_spans = []
        for match in URL_PATTERN.finditer(text):
            url = match.group().rstrip(".,;)")
            end = match.start() + len(url)
            url_spans.append((match.start(), end))
            add("urls", url, index, match.start(), end)
            try:
                host = urlsplit(url).hostname
            except ValueError:
                host = None
            if host:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    host_start = text.lower().find(host.lower(), match.start(), end)
                    if host_start >= 0:
                        add("domains", text[host_start:host_start + len(host)], index, host_start, host_start + len(host))

        path_spans = []
        for match in PATH_PATTERN.finditer(text):
            if any(match.start() < end and match.end() > start for start, end in url_spans):
                continue
            path_spans.append(match.span())
            add("file_paths", match.group(), index, match.start(), match.end())

        for match in DOMAIN_PATTERN.finditer(text):
            if any(match.start() < end and match.end() > start for start, end in url_spans + path_spans):
                continue
            if match.group().lower().rsplit(".", 1)[-1] in NON_DOMAIN_SUFFIXES:
                continue
            # Registry keys and path components often contain dotted product names,
            # which should not be reported as network domains.
            if (match.start() > 0 and text[match.start() - 1] in "\\/") or (
                match.end() < len(text) and text[match.end()] in "\\/"
            ):
                continue
            add("domains", match.group(), index, match.start(), match.end())

        if COMMAND_PATTERN.search(text):
            add("commands", text, index, 0, len(text))

    for items in categories.values():
        items.sort(key=lambda item: (item["value"].casefold(), item["string_offset"], item["match_start"]))
    return categories
