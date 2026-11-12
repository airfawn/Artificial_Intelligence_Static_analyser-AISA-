import json
from contextlib import nullcontext
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.behavior_analysis import analyze_report, build_evidence, main


def report():
    return {
        "status": "complete",
        "pe_metadata": {"hashes": {"sha256": "test-hash"}},
        "strings": [
            {"value": "browser profile", "offset": 42, "encoding": "ASCII"},
            {"value": "ftp://", "offset": 64, "encoding": "UTF-16LE"},
        ],
        "categorized_strings": {"urls": [], "domains": [], "file_paths": [], "commands": []},
        "apis": {
            "imports": [{"dll": "WS2_32.dll", "name": "connect", "ordinal": None}],
            "delay_imports": [], "exports": [],
        },
    }


def hypothesis(ids=None):
    return {
        "hypotheses": [{
            "possibility": "network communication", "support": "low",
            "explanation": "A networking import is present.",
            "evidence_ids": ids if ids is not None else ["imports0"],
            "limitations": "The import does not prove execution.",
        }],
        "summary": "Static evidence only.",
    }


class TestBehaviorAnalysis(unittest.TestCase):
    def test_analysis_preserves_references(self):
        result = analyze_report(report(), query=lambda *args: hypothesis())
        self.assertEqual(result["coverage"]["entries_examined"], 3)
        self.assertEqual([x["source"] for x in result["selected_evidence"]],
                         ["apis.imports[0]", "strings[1]", "strings[0]"])
        self.assertEqual(result["analysis"]["hypotheses"][0]["evidence_ids"], ["imports0"])

    def test_rejects_unknown_citation(self):
        with self.assertRaisesRegex(RuntimeError, "unknown evidence"):
            analyze_report(report(), query=lambda *args: hypothesis(["s999"]))

    def test_no_evidence_is_an_explicit_result(self):
        value = report()
        value["strings"] = []
        value["apis"]["imports"] = []
        result = analyze_report(value, query=lambda *args: self.fail("unexpected model call"))
        self.assertEqual(result["analysis"]["hypotheses"], [])
        self.assertIn("Insufficient", result["analysis"]["summary"])

    def test_invalid_and_incomplete_reports_fail(self):
        value = report()
        value["status"] = "incomplete"
        with self.assertRaisesRegex(ValueError, "complete"):
            build_evidence(value)
        value = report()
        value["apis"]["imports"] = None
        with self.assertRaisesRegex(ValueError, "unavailable"):
            build_evidence(value)

    def test_input_truncation_is_reported(self):
        value = report()
        value["strings"][0]["value"] = "x" * 1000
        result = analyze_report(value, query=lambda *args: hypothesis())
        self.assertEqual(result["coverage"]["entries_truncated"], 1)
        self.assertEqual(result["coverage"]["selected_values_shortened_for_model"], 1)

    def test_support_order(self):
        invalid = hypothesis(["s0"])
        invalid["hypotheses"].append({
            **invalid["hypotheses"][0], "support": "high",
        })
        result = analyze_report(report(), query=lambda *args: invalid)
        self.assertEqual([item["support"] for item in result["analysis"]["hypotheses"]],
                         ["high", "low"])

    def test_large_selection_is_bounded_with_visible_counts(self):
        value = report()
        value["strings"] = [{"value": f"test {i} " * 50, "offset": i, "encoding": "ASCII"}
                            for i in range(80)]

        def query(prompt, schema, model):
            return {"hypotheses": [], "summary": "Insufficient evidence."}

        result = analyze_report(value, query=query)
        self.assertGreater(result["coverage"]["entries_examined"],
                           result["coverage"]["entries_selected"])
        self.assertEqual(result["coverage"]["entries_examined"], 81)
        self.assertEqual(result["selected_evidence"][0]["id"], "imports0")

    def test_model_errors_do_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.json"
            source.write_text(json.dumps(report()), encoding="utf-8")
            output = Path(directory) / "result.json"
            with patch("core.behavior_analysis.query_model", side_effect=RuntimeError("server unavailable")):
                self.assertEqual(main([str(source), "--output", str(output)]), 1)
            self.assertFalse(output.exists())

    def test_frozen_analysis_uses_bundled_server(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.json"
            source.write_text(json.dumps(report()), encoding="utf-8")
            output = Path(directory) / "result.json"
            with patch("core.behavior_analysis.sys.frozen", True, create=True), \
                 patch("core.behavior_analysis.bundled_server",
                       return_value=nullcontext("http://127.0.0.1:1234/api/chat")) as server, \
                 patch("core.behavior_analysis.query_model", return_value=hypothesis()) as model:
                self.assertEqual(main([str(source), "--output", str(output)]), 0)
            server.assert_called_once()
            self.assertEqual(model.call_args.kwargs["endpoint"], "http://127.0.0.1:1234/api/chat")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["status"], "experimental")

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.json"
            source.write_text(json.dumps(report()), encoding="utf-8")
            output = Path(directory) / "result.json"
            output.write_text("existing", encoding="utf-8")
            self.assertEqual(main([str(source), "--output", str(output)]), 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")


if __name__ == "__main__":
    unittest.main()
