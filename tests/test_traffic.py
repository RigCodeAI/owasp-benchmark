import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from traffic import build_har, parse_crawler, require_local_target, target_url  # noqa: E402


class TrafficTests(unittest.TestCase):
    def test_request_semantics_and_url_rewrite(self):
        xml = """<?xml version="1.0"?>
        <benchmarkSuite>
          <benchmarkTest URL="https://localhost:8443/benchmark/x/BenchmarkTest00001" tcName="BenchmarkTest00001">
            <getparam name="q" value="safe value"/><header name="X-Test" value="one"/>
          </benchmarkTest>
          <benchmarkTest URL="https://localhost:8443/benchmark/y/BenchmarkTest00002" tcName="BenchmarkTest00002">
            <formparam name="name" value="safe"/><cookie name="session" value="two"/>
          </benchmarkTest>
        </benchmarkSuite>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crawler.xml"
            path.write_text(xml, encoding="utf-8")
            cases = parse_crawler(path)
        self.assertEqual(cases[0]["method"], "GET")
        self.assertEqual(cases[1]["method"], "POST")
        self.assertEqual(cases[0]["headers"], {"X-Test": "one"})
        self.assertEqual(cases[1]["cookies"], {"session": "two"})
        url = target_url(cases[0]["source_url"], "http://127.0.0.1:8000", cases[0]["query"])
        self.assertEqual(url, "http://127.0.0.1:8000/benchmark/x/BenchmarkTest00001?q=safe+value")

    def test_base_url_can_include_benchmark_path(self):
        url = target_url(
            "https://localhost:8443/benchmark/x/BenchmarkTest00001",
            "http://target:8000/benchmark",
            {},
        )
        self.assertEqual(url, "http://target:8000/benchmark/x/BenchmarkTest00001")

    def test_remote_targets_require_explicit_override(self):
        require_local_target("https://localhost:8443", False)
        require_local_target("http://127.0.0.1:8000", False)
        with self.assertRaises(ValueError):
            require_local_target("https://example.com", False)
        require_local_target("https://example.com", True)

    def test_har_preserves_request_inputs(self):
        cases = [
            {
                "case_id": "BenchmarkTest00001",
                "source_url": "https://localhost:8443/benchmark/x/BenchmarkTest00001",
                "method": "POST",
                "query": {},
                "form": {"name": "safe value"},
                "headers": {},
                "cookies": {"session": "safe value"},
            }
        ]
        request = build_har(cases, "http://127.0.0.1:8000")["log"]["entries"][0]["request"]
        self.assertEqual(request["postData"]["text"], "name=safe+value")
        self.assertIn({"name": "Cookie", "value": "session=safe%20value"}, request["headers"])


if __name__ == "__main__":
    unittest.main()
