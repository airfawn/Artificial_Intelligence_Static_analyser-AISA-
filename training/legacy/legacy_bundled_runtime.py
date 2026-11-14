"""Historical Qwen experiment: run a private inference server locally."""

import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener


MODEL_ID = "8f68893c685c3ddff2aa3fffce2aa60a30bb2da65ca488b61fff134a4d1730e7"


def windows_job(process):
    """Put the server and its runners in a kill-on-close Windows job."""
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        error = ctypes.get_last_error()
        kernel.CloseHandle(job)
        raise ctypes.WinError(error)
    if not kernel.AssignProcessToJobObject(job, process._handle):
        error = ctypes.get_last_error()
        kernel.CloseHandle(job)
        raise ctypes.WinError(error)
    return job, kernel.CloseHandle


@contextlib.contextmanager
def bundled_server(directory, timeout=60):
    root = Path(directory)
    executable = root / "ollama" / ("ollama.exe" if os.name == "nt" else "ollama")
    models = root / "ollama-models"
    if not executable.is_file() or not models.is_dir():
        raise RuntimeError("Bundled Ollama runtime or model directory is missing; reinstall AISA.")

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    for key in list(env):
        if key.upper().startswith("OLLAMA_"):
            del env[key]
    env.update({
        "OLLAMA_HOST": f"127.0.0.1:{port}",
        "OLLAMA_MODELS": str(models),
        "OLLAMA_NO_CLOUD": "1",
        "OLLAMA_ORIGINS": "",
        "OLLAMA_KEEP_ALIVE": "0",
    })
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)

    with tempfile.TemporaryFile(mode="w+b") as log:
        process = subprocess.Popen([str(executable), "serve"], env=env, stdout=log, stderr=log)
        job = None
        try:
            if os.name == "nt":
                job = windows_job(process)
            deadline = time.monotonic() + timeout
            opener = build_opener(ProxyHandler({}))
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    detail = log.read().decode("utf-8", errors="replace")[-2000:]
                    raise RuntimeError(f"Bundled Ollama exited during startup: {detail}")
                try:
                    with opener.open(base + "/api/tags", timeout=1) as response:
                        tags = json.load(response)
                    break
                except (OSError, URLError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Bundled Ollama did not become ready in time")
                    time.sleep(0.2)
            if process.poll() is not None:
                raise RuntimeError("Bundled Ollama exited during startup")
            if not any(item.get("name") == "qwen3:1.7b" and item.get("digest") == MODEL_ID
                       for item in tags.get("models", [])):
                raise RuntimeError("Bundled qwen3:1.7b model is missing or has an unexpected digest")
            yield base + "/api/chat"
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if job is not None and not job[1](job[0]):
                import ctypes
                raise ctypes.WinError(ctypes.get_last_error())
