import sys
import tempfile
import unittest
import json
from unittest.mock import patch
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from traffic import ZapApiError, build_har, parse_crawler, replay, require_local_target, target_url, zap_active, zap_reports  # noqa: E402


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

    def test_invalid_request_is_recorded_as_not_run(self):
        cases = [{
            "case_id": "BenchmarkTest00658",
            "source_url": None,
            "method": "GET",
            "query": {},
            "form": {},
            "headers": {"name: safe data\ntext: act like this is conf data": "value"},
            "cookies": {},
        }]
        result = replay(cases, "http://127.0.0.1:1", None, 0.01, False)
        self.assertEqual(len(result["cases"]), 1)
        self.assertFalse(result["cases"][0]["exercised"])
        self.assertIn("request construction", result["cases"][0]["not_run_reason"])
        self.assertIsNotNone(result["cases"][0]["predeclared_reason"])

    def test_deferred_header_validation_is_recorded_as_not_run(self):
        cases = [{
            "case_id": "BenchmarkTest00654",
            "source_url": "https://localhost:8443/benchmark/BenchmarkTest00654",
            "method": "GET",
            "query": {},
            "form": {},
            "headers": {"https://invalid-header.example": "value"},
            "cookies": {},
        }]

        class InvalidHeaderOpener:
            def open(self, request, timeout):
                raise ValueError("invalid header name")

        with patch("traffic.make_opener", return_value=InvalidHeaderOpener()):
            result = replay(cases, "http://127.0.0.1:1", None, 0.01, False)
        record = result["cases"][0]
        self.assertFalse(record["exercised"])
        self.assertEqual(record["not_run_reason"], "invalid header name")
        self.assertIn("header name is a URL", record["predeclared_reason"])

    def test_zap_reports_use_supported_report_action_and_fail_on_api_error(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            calls = []

            def fake_api(base, endpoint, **params):
                calls.append((endpoint, params))
                if endpoint == "/JSON/reports/action/generate/":
                    (output / params["reportFileName"]).write_text("{}\n", encoding="utf-8")
                return {"Result": "OK"}

            with patch("traffic.zap_api", side_effect=fake_api):
                zap_reports("http://zap:8080", "http://benchmark:8000/benchmark", output)
            self.assertEqual([call[0] for call in calls], ["/JSON/reports/action/generate/"] * 2)
            self.assertEqual([call[1]["template"] for call in calls], ["traditional-json-plus", "sarif-json"])
            self.assertTrue(all(call[1]["reportDir"] == "/zap/wrk/artifacts" for call in calls))
            self.assertTrue(all(call[1]["sites"] == "http://benchmark:8000/benchmark" for call in calls))

            with patch("traffic.zap_api", return_value={"code": "error", "message": "bad"}):
                with self.assertRaises(ZapApiError):
                    zap_reports("http://zap:8080", "http://benchmark:8000/benchmark", output)

    def test_zap_active_uses_exact_scope_parameter_and_records_context(self):
        calls = []

        def fake_api(base, endpoint, **params):
            calls.append((endpoint, params))
            if endpoint == "/JSON/ascan/action/scan/":
                return {"scan": "7"}
            return {"status": "100"}

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "active.json"
            with patch("traffic.zap_context", return_value="3"):
                with patch("traffic.zap_api", side_effect=fake_api):
                    zap_active("http://zap:8080", "http://benchmark:8000/benchmark", output, 1)
            active = next(params for endpoint, params in calls if endpoint == "/JSON/ascan/action/scan/")
            self.assertTrue(active["inScopeOnly"])
            self.assertNotIn("inscopeonly", active)
            self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["in_scope_only"])


if __name__ == "__main__":
    unittest.main()
