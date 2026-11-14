"""Download a bounded, pinned set of public CAPE JSON reports, never executables."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen


REVISION = "dbda5905c9dd0cb00acdc33d9a63dd5000381e16"
DATASET = "Thcrull/win-exe-malware-analysis"
DIRECTORIES = {
    "malware": "malware_reports/reports",
    "benign": "benign_reports/Benign-NET/reports",
    "portableapps": "benign_reports/PortableApps/reports",
    "installers": "benign_reports/PortableAppsInstallers/reports",
    "sysinternals": "benign_reports/SysinternalsSuite/reports",
}
MAX_REPORT_BYTES = 5_000_000


def catalog(directory):
    url = f"https://huggingface.co/api/datasets/{DATASET}/tree/{REVISION}/{directory}?limit=100"
    with urlopen(url, timeout=60) as response:
        entries = json.load(response)
    return [
        entry for entry in entries
        if entry.get("type") == "file"
        and entry.get("path", "").startswith(directory + "/")
        and entry["path"].endswith(".json")
        and 0 < entry["size"] <= MAX_REPORT_BYTES
        and "lfs" not in entry
    ]


def download(entry, directory):
    source = entry["path"]
    url = f"https://huggingface.co/datasets/{DATASET}/resolve/{REVISION}/{quote(source)}"
    with urlopen(url, timeout=120) as response:
        payload = response.read(MAX_REPORT_BYTES + 1)
    if len(payload) != entry["size"]:
        raise ValueError(f"Unexpected size for {source}")
    git_hash = hashlib.sha1(f"blob {len(payload)}\0".encode() + payload).hexdigest()
    if git_hash != entry["oid"]:
        raise ValueError(f"Git blob hash mismatch for {source}")
    report = json.loads(payload)
    if not isinstance(report, dict):
        raise ValueError(f"Report is not a JSON object: {source}")
    destination = directory / Path(source).name
    with destination.open("xb") as file:
        file.write(payload)
    return {
        "source_path": source,
        "file": str(destination.relative_to(directory.parent)),
        "git_blob_sha1": git_hash,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New dataset directory")
    parser.add_argument("--per-class", type=int, default=20, choices=range(1, 101))
    parser.add_argument("--source", action="append", choices=tuple(DIRECTORIES),
                        help="Report source; repeat to select multiple (default: malware and benign)")
    args = parser.parse_args()
    sources = args.source if args.source else ["malware", "benign"]
    if len(set(sources)) != len(sources):
        parser.error("Each report source may be selected only once")
    destination = Path(args.output)
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {
        "dataset": DATASET,
        "revision": REVISION,
        "license": "MIT (dataset card)",
        "selection": "first non-LFS JSON reports <= 5 MB in first catalog page; not representative",
        "records": [],
    }
    for source in sources:
        remote_directory = DIRECTORIES[source]
        label = "malware" if source == "malware" else "benign"
        records = catalog(remote_directory)
        if not records:
            raise RuntimeError(f"No eligible reports found for {source}")
        if len(records) < args.per_class:
            print(f"Only {len(records)} eligible reports found for {source}; downloading all.")
        local = destination / source
        local.mkdir()
        for entry in records[:args.per_class]:
            record = download(entry, local)
            record["dataset_partition"] = label
            record["source_group"] = source
            manifest["records"].append(record)
            print(f"Downloaded {label}: {record['file']}", flush=True)
    with (destination / "manifest.json").open("x", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)
    print(f"Downloaded {len(manifest['records'])} reports to {destination}")


if __name__ == "__main__":
    main()
