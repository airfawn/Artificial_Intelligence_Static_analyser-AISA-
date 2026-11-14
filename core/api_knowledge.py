"""Conservative descriptions of selected Windows APIs and import combinations."""

CAPABILITIES = {
    "readfile": "Can read data from a file or other handle.",
    "writefile": "Can write data to a file or other handle.",
    "createfilea": "Can open or create files or other objects.",
    "createfilew": "Can open or create files or other objects.",
    "internetreadfile": "Can read data from an internet connection.",
    "urldownloadtofilea": "Can download a URL to a file.",
    "urldownloadtofilew": "Can download a URL to a file.",
    "winhttpsendrequest": "Can send an HTTP request, potentially including data.",
    "httpsendrequesta": "Can send an HTTP request, potentially including data.",
    "httpsendrequestw": "Can send an HTTP request, potentially including data.",
    "send": "Can send data over a socket.",
    "regsetvalueexa": "Can set registry values; the target key determines the effect.",
    "regsetvalueexw": "Can set registry values; the target key determines the effect.",
    "regopenkeyexa": "Can open registry keys.",
    "regopenkeyexw": "Can open registry keys.",
    "writeprocessmemory": "Can write memory in another process with appropriate access.",
    "createremotethread": "Can create a thread in another process with appropriate access.",
    "virtualallocex": "Can allocate memory in another process with appropriate access.",
    "createprocessa": "Can start a process.",
    "createprocessw": "Can start a process.",
    "shellexecutea": "Can open a file or launch an associated program.",
    "shellexecutew": "Can open a file or launch an associated program.",
    "setfileattributesa": "Can change file attributes, including the hidden attribute.",
    "setfileattributesw": "Can change file attributes, including the hidden attribute.",
    "cryptencrypt": "Can encrypt data; encryption also has legitimate uses.",
    "bcryptencrypt": "Can encrypt data; encryption also has legitimate uses.",
    "getprocaddress": "Can resolve exported functions at runtime; resolved APIs may not appear in imports.",
    "loadlibrarya": "Can load a library at runtime.",
    "loadlibraryw": "Can load a library at runtime.",
    "isdebuggerpresent": "Can check whether the current process is being debugged.",
    "virtualprotect": "Can change memory page protections.",
}

# Each group is an OR of exact API names; a pair requires one API from each group.
PATTERNS = {
    "file_read_and_network_send": {
        "groups": (("readfile",), ("send", "winhttpsendrequest", "httpsendrequesta", "httpsendrequestw")),
        "description": "May support reading data and sending data over a network; this does not establish exfiltration.",
    },
    "remote_memory_and_thread": {
        "groups": (("writeprocessmemory",), ("createremotethread",)),
        "description": "May support writing to another process and creating a thread there; this does not establish injection.",
    },
    "download_and_launch": {
        "groups": (("urldownloadtofilea", "urldownloadtofilew", "internetreadfile"),
                   ("createprocessa", "createprocessw", "shellexecutea", "shellexecutew")),
        "description": "May support downloading data and launching a program; a downloaded program was not established.",
    },
    "registry_open_and_write": {
        "groups": (("regopenkeyexa", "regopenkeyexw"), ("regsetvalueexa", "regsetvalueexw")),
        "description": "May support changing registry settings; persistence depends on the specific key and value.",
    },
    "load_library_and_resolve_api": {
        "groups": (("loadlibrarya", "loadlibraryw"), ("getprocaddress",)),
        "description": "May support resolving library functions dynamically; this is also common in legitimate software.",
    },
}


def pattern_matches(names, pattern):
    return all(any(name in names for name in group) for group in pattern["groups"])
