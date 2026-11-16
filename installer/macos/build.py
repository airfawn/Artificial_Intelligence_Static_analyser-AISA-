#!/usr/bin/env python3
"""Build a self-contained macOS installer on the target architecture."""

import argparse
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from aisa_version import __version__


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upx", type=Path, required=True, help="Native UPX executable")
    parser.add_argument("--upx-license-dir", type=Path, required=True,
                        help="Directory containing UPX COPYING and LICENSE")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "macos")
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() not in ("arm64", "x86_64"):
        parser.error("Build on the target macOS arm64 or x86_64 architecture")
    if not args.upx.is_file():
        parser.error(f"UPX executable not found: {args.upx}")
    for name in ("COPYING", "LICENSE"):
        if not (args.upx_license_dir / name).is_file():
            parser.error(f"UPX license file not found: {args.upx_license_dir / name}")

    subprocess.run([str(args.upx), "--version"], check=True)
    libraries = subprocess.run(["otool", "-L", str(args.upx)], check=True,
                               capture_output=True, text=True).stdout.splitlines()[1:]
    for line in libraries:
        library = line.strip().split(" (", 1)[0]
        if not library.startswith(("/usr/lib/", "/System/Library/")):
            raise RuntimeError(f"UPX depends on an unbundled library: {library}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    destination = args.output_dir.resolve() / f"AISA-Setup-macOS-{platform.machine()}.pkg"
    if destination.exists():
        raise FileExistsError(f"Output already exists: {destination}")
    with tempfile.TemporaryDirectory(prefix="aisa-macos-build-") as directory:
        temporary = Path(directory)
        command = [
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--noupx", "--onedir",
            "--console", "--name", "aisa", "--paths", str(ROOT),
            "--distpath", str(temporary / "dist"), "--workpath", str(temporary / "work"),
            "--specpath", str(temporary),
        ]
        for name in ("string_model_weights.json", "packing_model.json", "api_frequency_model.json"):
            command.extend(["--add-data", f"{ROOT / 'models' / name}:models"])
        subprocess.run([*command, str(ROOT / "main.py")], check=True, cwd=ROOT)

        app = temporary / "dist" / "aisa"
        upx_dir = app / "upx"
        upx_dir.mkdir()
        shutil.copy2(args.upx, upx_dir / "upx")
        for name in ("COPYING", "LICENSE"):
            shutil.copy2(args.upx_license_dir / name, upx_dir / name)
        subprocess.run([sys.executable, str(ROOT / "installer" / "smoke_test.py"), str(app / "aisa")],
                       check=True, cwd=ROOT)

        payload = temporary / "payload"
        library_dir = payload / "usr" / "local" / "lib"
        library_dir.mkdir(parents=True)
        shutil.copytree(app, library_dir / "aisa", symlinks=True)
        bin_dir = payload / "usr" / "local" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "aisa").symlink_to("/usr/local/lib/aisa/aisa")
        subprocess.run([
            "pkgbuild", "--root", str(payload), "--identifier", "com.aisa.static-analysis",
            "--version", __version__, "--install-location", "/", "--ownership", "recommended",
            str(destination),
        ], check=True)
    print(f"Installer created: {destination}")


if __name__ == "__main__":
    main()
