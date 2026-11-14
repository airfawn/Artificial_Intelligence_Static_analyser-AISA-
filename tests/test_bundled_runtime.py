import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.request import urlopen

from training.legacy.legacy_bundled_runtime import MODEL_ID, bundled_server


@unittest.skipIf(os.name == "nt", "The fake runtime fixture is a Unix executable")
class TestBundledRuntime(unittest.TestCase):
    def make_runtime(self, root, model_id=MODEL_ID):
        executable = root / "ollama" / "ollama"
        executable.parent.mkdir()
        (root / "ollama-models").mkdir()
        executable.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os\n"
            "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            " def do_GET(self):\n"
            "  self.send_response(200)\n"
            "  self.end_headers()\n"
            f"  self.wfile.write(json.dumps({{'models':[{{'name':'qwen3:1.7b','digest':'{model_id}'}}]}}).encode())\n"
            "HTTPServer(('127.0.0.1', int(os.environ['OLLAMA_HOST'].rsplit(':',1)[1])), Handler).serve_forever()\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable

    def test_server_is_private_and_stops_after_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_runtime(root)
            with bundled_server(root) as endpoint:
                with urlopen(endpoint.replace("/api/chat", "/api/tags"), timeout=2) as response:
                    self.assertEqual(json.load(response)["models"][0]["digest"], MODEL_ID)
            with self.assertRaises(OSError):
                urlopen(endpoint.replace("/api/chat", "/api/tags"), timeout=2)

    def test_wrong_model_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_runtime(root, model_id="wrong")
            with self.assertRaisesRegex(RuntimeError, "unexpected digest"):
                with bundled_server(root):
                    self.fail("unexpected readiness")

    def test_missing_runtime_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "missing"):
                with bundled_server(directory):
                    self.fail("unexpected readiness")


if __name__ == "__main__":
    unittest.main()
