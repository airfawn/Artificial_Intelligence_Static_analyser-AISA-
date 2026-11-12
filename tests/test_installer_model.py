import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from installer.windows.verify_model import verify


class TestInstallerModel(unittest.TestCase):
    def test_verifies_manifest_and_blob_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b"model fixture"
            blob_hash = hashlib.sha256(data).hexdigest()
            blob = root / "blobs" / f"sha256-{blob_hash}"
            blob.parent.mkdir()
            blob.write_bytes(data)
            manifest = root / "manifests" / "registry.ollama.ai" / "library" / "qwen3" / "1.7b"
            manifest.parent.mkdir(parents=True)
            content = json.dumps({
                "config": {"digest": f"sha256:{blob_hash}", "size": len(data)},
                "layers": [],
            }).encode()
            manifest.write_bytes(content)
            with patch("installer.windows.verify_model.EXPECTED_MANIFEST", hashlib.sha256(content).hexdigest()):
                verify(root)
                blob.write_bytes(b"tampered data")
                with self.assertRaisesRegex(ValueError, "failed verification"):
                    verify(root)
            manifest.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "manifest"):
                verify(root)


if __name__ == "__main__":
    unittest.main()
