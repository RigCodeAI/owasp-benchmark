import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from verify_lock import verify  # noqa: E402


class VerifyLockTests(unittest.TestCase):
    def test_verifies_hashes_and_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = b"BenchmarkTest00001,path,true,22\nBenchmarkTest00002,path,false,22\n"
            (root / "expected.csv").write_bytes(expected)
            (root / "openapi.yaml").write_bytes(
                b"openapi: 3.0.0\npaths:\n  /BenchmarkTest00001: {}\n  /BenchmarkTest00002: {}\n"
            )
            (root / "crawler.xml").write_bytes(
                b'<benchmarkSuite><benchmarkTest tcName="BenchmarkTest00001"/>'
                b'<benchmarkTest tcName="BenchmarkTest00002"/></benchmarkSuite>\n'
            )
            artifacts = {}
            for name, filename in (("expected_results", "expected.csv"), ("openapi", "openapi.yaml"), ("crawler", "crawler.xml")):
                artifacts[name] = {"path": filename, "sha256": hashlib.sha256((root / filename).read_bytes()).hexdigest()}
            lock = {
                "commit": "unused",
                "counts": {"cases": 2, "vulnerable": 1, "safe": 1, "cwes": 1},
                "artifacts": artifacts,
            }
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            self.assertEqual(verify(root, lock_path), [])


if __name__ == "__main__":
    unittest.main()
