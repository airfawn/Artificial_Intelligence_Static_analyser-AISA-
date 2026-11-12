"""Build a feature-only dataset from pinned public Windows wheels and UPX."""

import argparse
import hashlib
import io
import json
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from core.pe_analyzer import PEAnalyzer
from core.packing_model import extract_packing_features
from training.packing_baseline import write_json


# The split is by project, not by wheel member or original/packed pair.
PROJECTS = (
    ("psutil", "7.2.2", "train"),
    ("bcrypt", "5.0.0", "train"),
    ("pyyaml", "6.0.3", "train"),
    ("pillow", "13.0.0", "train"),
    ("markupsafe", "3.0.4", "train"),
    ("charset-normalizer", "3.5.2", "train"),
    ("cffi", "2.1.1", "train"),
    ("zstandard", "0.25.0", "train"),
    ("orjson", "3.13.0", "train"),
    ("multidict", "7.2.1", "train"),
    ("lxml", "6.1.3", "test"),
    ("pyzmq", "27.3.0", "test"),
    ("regex", "2026.11.9", "test"),
    ("pydantic-core", "2.50.4", "test"),
)
MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_MEMBER = 20 * 1024 * 1024
MAX_MEMBERS_PER_PROJECT = 4
LIMITATIONS = (
    "UPX versus packable public Windows wheel binaries only. Negative examples are "
    "assumed unpacked; they are not independently certified against other packers. "
    "The split is by PyPI project, not verified independent code lineage. "
    "Other packers, malware, signed binaries and other architectures are not represented."
)


def _read_url(url, host, limit):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != host:
        raise ValueError(f"Unexpected download URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "AISA-packing-dataset/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        final = urlparse(response.geturl())
        if final.scheme != "https" or final.hostname != host:
            raise ValueError(f"Unexpected redirect URL: {response.geturl()}")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Download exceeds {limit} bytes: {url}")
    return data


def _select_wheel(files):
    candidates = [
        item for item in files
        if item["filename"].endswith("win_amd64.whl")
        and ("-cp311-cp311-" in item["filename"] or "-abi3-" in item["filename"])
        and not item.get("yanked")
    ]
    if not candidates:
        raise ValueError("No compatible Windows wheel found")
    return sorted(candidates, key=lambda item: (
        "-cp311-cp311-" not in item["filename"], item["filename"]
    ))[0]


def _features(path):
    analyzer = PEAnalyzer(str(path))
    if not analyzer.is_valid_pe or not analyzer.pe or not analyzer.pe.sections:
        raise ValueError(f"Not a valid PE with sections: {path}")
    packing = analyzer.analyze_packing()
    return extract_packing_features(packing), packing["weighted_score"]


def create_dataset(upx):
    version = subprocess.run([upx, "--version"], check=True, capture_output=True,
                             text=True, timeout=60).stdout.splitlines()[0]
    samples, sources, rejected = [], [], []
    seen = set()
    with tempfile.TemporaryDirectory(prefix="aisa-public-packing-") as directory:
        temp = Path(directory)
        for project, release, split in PROJECTS:
            metadata_url = f"https://pypi.org/pypi/{project}/{release}/json"
            metadata = json.loads(_read_url(metadata_url, "pypi.org", 8 * 1024 * 1024))
            wheel = _select_wheel(metadata["urls"])
            content = _read_url(wheel["url"], "files.pythonhosted.org", MAX_DOWNLOAD)
            digest = hashlib.sha256(content).hexdigest()
            if digest != wheel["digests"]["sha256"]:
                raise ValueError(f"Wheel hash mismatch: {wheel['filename']}")
            sources.append({
                "project": project, "version": release, "split": split,
                "metadata_url": metadata_url, "wheel_url": wheel["url"],
                "wheel_filename": wheel["filename"], "wheel_sha256": digest,
            })
            accepted = 0
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = sorted(
                    (entry for entry in archive.infolist()
                     if entry.filename.lower().endswith((".exe", ".dll", ".pyd"))
                     and not entry.is_dir()),
                    key=lambda entry: entry.filename,
                )
                for entry in members:
                    if accepted >= MAX_MEMBERS_PER_PROJECT:
                        break
                    if entry.file_size > MAX_MEMBER:
                        rejected.append({"project": project, "member": entry.filename, "reason": "member too large"})
                        continue
                    binary = archive.read(entry)
                    original_hash = hashlib.sha256(binary).hexdigest()
                    if original_hash in seen:
                        rejected.append({"project": project, "member": entry.filename, "reason": "duplicate original"})
                        continue
                    original, packed = temp / "input.exe", temp / "packed.exe"
                    original.write_bytes(binary)
                    if packed.exists():
                        packed.unlink()
                    result = subprocess.run([upx, "-o", str(packed), str(original)],
                                            capture_output=True, timeout=60)
                    if result.returncode:
                        diagnostic = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
                        rejected.append({"project": project, "member": entry.filename,
                                         "reason": f"UPX exit {result.returncode}: {diagnostic[-500:]}"})
                        continue
                    subprocess.run([upx, "-t", str(packed)], check=True,
                                   capture_output=True, timeout=60)
                    original_features, packed_features = _features(original), _features(packed)
                    seen.add(original_hash)
                    for path, label, (features, score) in ((original, "unpacked", original_features),
                                                           (packed, "UPX", packed_features)):
                        samples.append({
                            "project": project, "member": entry.filename,
                            "group_sha256": original_hash,
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "split": split, "label": label, "features": features,
                            "weighted_score": score,
                        })
                    accepted += 1
            if not accepted:
                raise ValueError(f"No packable PE members in {project} {release}")
            print(f"{project}: {accepted} pairs ({split})", flush=True)
    return {
        "version": 1, "source": "Pinned PyPI Windows wheels and UPX-packed copies",
        "upx_version": version, "limitations": LIMITATIONS, "sources": sources,
        "rejected": rejected, "samples": samples,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upx", default="upx")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists")
    write_json(args.output, create_dataset(args.upx))
    print(f"Dataset saved to {args.output}")


if __name__ == "__main__":
    main()
