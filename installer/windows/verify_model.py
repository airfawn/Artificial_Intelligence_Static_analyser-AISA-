"""Verify the exact Ollama model manifest and all of its referenced blobs."""

import hashlib
import json
import sys
from pathlib import Path

EXPECTED_MANIFEST = "8f68893c685c3ddff2aa3fffce2aa60a30bb2da65ca488b61fff134a4d1730e7"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def verify(root):
    root = Path(root)
    manifest = root / "manifests" / "registry.ollama.ai" / "library" / "qwen3" / "1.7b"
    if digest(manifest) != EXPECTED_MANIFEST:
        raise ValueError("Unexpected qwen3:1.7b manifest digest")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    for entry in [data["config"], *data["layers"]]:
        algorithm, hash_value = entry["digest"].split(":", 1)
        if algorithm != "sha256" or len(hash_value) != 64:
            raise ValueError("Invalid blob digest in model manifest")
        blob = root / "blobs" / f"sha256-{hash_value}"
        if blob.stat().st_size != entry["size"] or digest(blob) != hash_value:
            raise ValueError(f"Model blob failed verification: {hash_value}")
    return data


if __name__ == "__main__":
    verify(sys.argv[1])
    print("Verified qwen3:1.7b model manifest and blobs.")
