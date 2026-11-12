import hashlib
import io
import json
import subprocess
import unittest
import zipfile
from unittest.mock import patch

from training.packing_public import create_dataset, _select_wheel


class TestPublicPackingData(unittest.TestCase):
    def test_selects_cp311_wheel_and_skips_yanked(self):
        files = [
            {"filename": "pkg-1-cp37-abi3-win_amd64.whl"},
            {"filename": "pkg-1-cp311-cp311-win_amd64.whl"},
            {"filename": "pkg-1-cp311-cp311-win32.whl"},
            {"filename": "aaa-1-cp311-cp311-win_amd64.whl", "yanked": True},
        ]
        self.assertEqual(_select_wheel(files)["filename"], "pkg-1-cp311-cp311-win_amd64.whl")
        with self.assertRaisesRegex(ValueError, "No compatible"):
            _select_wheel([])

    def test_builds_paired_features_and_checks_wheel_hash(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("package/a.pyd", b"sample PE")
        wheel = buffer.getvalue()
        metadata = {"urls": [{
            "filename": "pkg-1-cp311-cp311-win_amd64.whl",
            "url": "https://files.pythonhosted.org/pkg.whl",
            "digests": {"sha256": hashlib.sha256(wheel).hexdigest()},
        }]}

        def read_url(url, host, limit):
            return json.dumps(metadata).encode() if host == "pypi.org" else wheel

        def run(command, **kwargs):
            if command[1] == "--version":
                return subprocess.CompletedProcess(command, 0, stdout="upx test\n")
            if command[1] == "-o":
                from pathlib import Path
                Path(command[2]).write_bytes(b"packed PE")
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        with patch("training.packing_public.PROJECTS", (("pkg", "1", "train"),)), \
             patch("training.packing_public._read_url", side_effect=read_url), \
             patch("training.packing_public._features", return_value=({"example": 1.0}, {"score": 0.0})), \
             patch("training.packing_public.subprocess.run", side_effect=run):
            dataset = create_dataset("upx")
            self.assertEqual([row["label"] for row in dataset["samples"]], ["unpacked", "UPX"])
            self.assertEqual(dataset["samples"][0]["weighted_score"]["score"], 0.0)
            self.assertEqual(dataset["samples"][0]["group_sha256"], dataset["samples"][1]["group_sha256"])
            metadata["urls"][0]["digests"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                create_dataset("upx")


if __name__ == "__main__":
    unittest.main()
