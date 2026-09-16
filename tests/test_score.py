import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from score import score  # noqa: E402


class ScoreTests(unittest.TestCase):
    def test_strict_matching_deduplication_aliases_and_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "expected.csv"
            findings = root / "findings.jsonl"
            aliases = root / "aliases.json"
            coverage = root / "coverage.json"
            expected.write_text(
                "# header\nBenchmarkTest00001,path,true,22\n"
                "BenchmarkTest00002,path,false,22\n"
                "BenchmarkTest00003,redirect,true,328\n",
                encoding="utf-8",
            )
            rows = [
                {"case_id": "BenchmarkTest00001", "cwes": ["CWE-23"]},
                {"case_id": "BenchmarkTest00001", "cwes": [23]},
                {"case_id": "BenchmarkTest00002", "cwes": [22]},
                {"case_id": "BenchmarkTest00003", "cwes": [79]},
                {"case_id": "BenchmarkTest99999", "cwes": [22]},
                {"case_id": None, "cwes": [22]},
            ]
            findings.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            aliases.write_text('{"23": 22, "916": 328}\n', encoding="utf-8")
            coverage.write_text(
                json.dumps(
                    {
                        "cases": [
                            {"case_id": "BenchmarkTest00001", "exercised": True},
                            {"case_id": "BenchmarkTest00002", "exercised": False},
                            {"case_id": "BenchmarkTest00003", "exercised": True},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = score(expected, findings, aliases, coverage)

        self.assertEqual(result["all_cases"]["tp"], 1)
        self.assertEqual(result["all_cases"]["fn"], 1)
        self.assertEqual(result["all_cases"]["fp"], 1)
        self.assertEqual(result["all_cases"]["tn"], 0)
        self.assertEqual(result["diagnostics"]["duplicate_detection_pairs"], 1)
        self.assertEqual(result["diagnostics"]["unknown_case_pairs"], 1)
        self.assertEqual(result["diagnostics"]["unmatched_detection_pairs"], 2)
        self.assertEqual(result["coverage"]["exercised"], 2)
        self.assertEqual(result["coverage"]["not_run"], 1)
        self.assertEqual(result["covered_cases"]["tp"], 1)
        self.assertEqual(result["covered_cases"]["fn"], 1)
        self.assertEqual(result["covered_cases"]["safe"], 0)


if __name__ == "__main__":
    unittest.main()
