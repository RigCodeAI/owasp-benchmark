import sys
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from normalize_sarif import normalize  # noqa: E402


class NormalizeSarifTests(unittest.TestCase):
    def test_extracts_case_and_rule_cwe(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Example",
                            "rules": [
                                {
                                    "id": "rule.path",
                                    "name": "Path traversal",
                                    "properties": {"tags": ["security", "CWE-23"]},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "rule.path",
                            "level": "error",
                            "message": {"text": "tainted path"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "BenchmarkTest00042.py"},
                                        "region": {"startLine": 12},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        findings, diagnostics = normalize(sarif, {23: 22}, "input.sarif")
        self.assertEqual(findings[0]["case_id"], "BenchmarkTest00042")
        self.assertEqual(findings[0]["cwes"], ["CWE-22"])
        self.assertEqual(findings[0]["line"], 12)
        self.assertEqual(diagnostics["without_case_id"], 0)
        self.assertEqual(diagnostics["without_cwe"], 0)

    def test_keeps_unmapped_findings_visible(self):
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"name": "Example"}},
                    "results": [{"ruleId": "unknown", "message": {"text": "generic issue"}}],
                }
            ]
        }
        findings, diagnostics = normalize(sarif, {}, "input.sarif")
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["case_id"])
        self.assertEqual(findings[0]["cwes"], [])
        self.assertEqual(diagnostics["without_case_id"], 1)
        self.assertEqual(diagnostics["without_cwe"], 1)


if __name__ == "__main__":
    unittest.main()
