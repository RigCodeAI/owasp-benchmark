import json
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from aggregate import aggregate  # noqa: E402
from codeql_metadata import capture, public_value  # noqa: E402
from freeze_semgrep import freeze, provenance, verify as verify_rules  # noqa: E402
from run_manifest import create_manifest, validate_run  # noqa: E402
from source_scope import prepare, verify as verify_scope  # noqa: E402
from zap_automation import make_boundary, validate_alert_canary, validate_coverage, validate_history, validate_plan  # noqa: E402
from validate_sarif import SarifError, validate  # noqa: E402


SHA = "a" * 40


def metrics():
    return {
        "cases": 2,
        "vulnerable": 1,
        "safe": 1,
        "tp": 1,
        "fn": 0,
        "fp": 0,
        "tn": 1,
        "recall": 1.0,
        "false_positive_rate": 0.0,
        "by_cwe": {"CWE-22": {"tp": 1, "fn": 0, "fp": 0, "tn": 1}},
    }


class Phase0HarnessTests(unittest.TestCase):
    def test_sarif_validator_rejects_empty_or_malformed_documents(self):
        with self.assertRaises(SarifError):
            validate({})
        valid = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "fixture", "rules": [{"id": "r"}]}},
                "results": [{
                    "ruleId": "r",
                    "message": {"text": "finding"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}],
                }],
            }],
        }
        validate(valid)
        invalid = json.loads(json.dumps(valid))
        invalid["runs"][0]["results"][0]["message"] = {}
        with self.assertRaises(SarifError):
            validate(invalid)

    def test_scope_excludes_outputs_and_retains_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "benchmark"
            source.mkdir()
            (source / "app.py").write_text("import helper\n", encoding="utf-8")
            (source / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
            (source / "source-scope.json").write_text("generated metadata\n", encoding="utf-8")
            (source / "SHA256SUMS").write_text("generated checksums\n", encoding="utf-8")
            (source / "results").mkdir()
            (source / "results" / "old.sarif").write_text("{}", encoding="utf-8")
            (source / ".git").mkdir()
            (source / ".git" / "HEAD").write_text("secret", encoding="utf-8")
            (source / "venv").mkdir()
            (source / "venv" / "python").write_text("binary", encoding="utf-8")
            destination = root / "scope"
            manifest = prepare(source, destination, source_commit=SHA)
            self.assertTrue((destination / "tree" / "app.py").is_file())
            self.assertTrue((destination / "tree" / "helper.py").is_file())
            self.assertFalse((destination / "tree" / "results").exists())
            self.assertFalse((destination / "tree" / ".git").exists())
            self.assertFalse((destination / "tree" / "source-scope.json").exists())
            self.assertFalse((destination / "tree" / "SHA256SUMS").exists())
            self.assertEqual(verify_scope(destination / "source-scope.json"), [])
            (destination / "tree" / "added.py").write_text("x = 1\n", encoding="utf-8")
            self.assertTrue(verify_scope(destination / "source-scope.json"))
            self.assertTrue(manifest["tree_sha256"])

    def test_frozen_rules_reject_registry_and_detect_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                freeze("p/python", root / "rules.yml")
            source = root / "resolved.yml"
            source.write_text("rules:\n  - id: test\n", encoding="utf-8")
            frozen = root / "rules.yml"
            record = freeze(str(source), frozen, resolved_from="p/python")
            self.assertTrue(record["frozen"])
            self.assertFalse(record["publishable"])
            self.assertEqual(record["license"], {
                "id": "Semgrep Rules License v1.0",
                "url": "https://semgrep.dev/legal/rules-license/",
            })
            self.assertEqual(record["redistribution"], "prohibited")
            self.assertFalse(record["redistribution_allowed"])
            self.assertEqual(record["rule_count"], 1)
            self.assertTrue(record["source_url"].startswith("https://"))
            self.assertTrue(record["license"]["id"])
            self.assertEqual(verify_rules(frozen, root / "rules.yml.manifest.json"), [])
            sanitized = root / "provenance.json"
            provenance(
                root / "rules.yml.manifest.json",
                sanitized,
                expected_sha256=record["sha256"],
                expected_rule_count=1,
            )
            sanitized_value = json.loads(sanitized.read_text(encoding="utf-8"))
            self.assertEqual(sanitized_value["license"]["id"], "Semgrep Rules License v1.0")
            self.assertFalse(sanitized_value["redistribution_allowed"])
            self.assertNotIn("rules", sanitized_value)
            original = json.loads((root / "rules.yml.manifest.json").read_text(encoding="utf-8"))
            for key, bad_value in {
                "source_url": "https://semgrep.dev/c/p/changed",
                "source_ref": "p/changed",
                "cli_mode": "pro",
                "account_status": "authenticated",
                "auth_status": "token",
            }.items():
                tampered = dict(original)
                tampered[key] = bad_value
                (root / "rules.yml.manifest.json").write_text(json.dumps(tampered), encoding="utf-8")
                self.assertTrue(verify_rules(frozen, root / "rules.yml.manifest.json"))
            (root / "rules.yml.manifest.json").write_text(json.dumps(original), encoding="utf-8")
            frozen.chmod(stat.S_IRUSR | stat.S_IWUSR)
            self.assertTrue(verify_rules(frozen, root / "rules.yml.manifest.json"))
            record = json.loads((root / "rules.yml.manifest.json").read_text(encoding="utf-8"))
            record["redistribution_allowed"] = True
            (root / "rules.yml.manifest.json").write_text(json.dumps(record), encoding="utf-8")
            self.assertTrue(verify_rules(frozen, root / "rules.yml.manifest.json"))

    def test_codeql_metadata_records_archive_and_resolved_pack_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "codeql-bundle"
            bundle.mkdir()
            executable = bundle / "codeql"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then printf '%s\\n' '{\"version\":\"2.27.0\"}'; else printf '%s\\n' 'codeql/python-queries@1.8.10'; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            pack = root / "python-queries"
            pack.mkdir()
            (pack / "qlpack.yml").write_text("name: codeql/python-queries\nversion: 1.8.10\n", encoding="utf-8")
            suite = pack / "codeql-suites" / "python-security-extended.qls"
            suite.parent.mkdir()
            suite.write_text("- from: codeql/suite-helpers\n", encoding="utf-8")
            archive = root / "codeql-bundle.tar.gz"
            archive.write_bytes(b"pinned bundle archive fixture")
            output = root / "metadata.json"
            value = capture(
                bundle,
                pack,
                str(suite),
                output,
                archive=archive,
                archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                query_pack_version="1.8.10",
            )
            self.assertEqual(value["bundle"]["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(value["query_pack"]["version"], "1.8.10")
            self.assertEqual(value["suite"]["name"], "python-security-extended.qls")
            self.assertEqual(value["suite"]["path"], "codeql-suites/python-security-extended.qls")
            self.assertNotIn(str(root), output.read_text(encoding="utf-8"))
            self.assertEqual(public_value(r"C:\\Users\\runner\\codeql\\codeql"), "codeql")
            outside_suite = root / "outside" / "python-security-extended.qls"
            outside_suite.parent.mkdir()
            outside_suite.write_text("- from: codeql/suite-helpers\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                capture(
                    bundle,
                    pack,
                    str(outside_suite),
                    root / "outside-metadata.json",
                    archive=archive,
                    archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                    query_pack_version="1.8.10",
                )

    def test_manifest_checksums_and_schema_validation_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
            artifacts = root / "run"
            artifacts.mkdir()
            scope = artifacts / "source-scope"
            prepare(source, scope, source_commit=SHA)
            (artifacts / "raw.sarif").write_text(json.dumps({
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
            }) + "\n", encoding="utf-8")
            (artifacts / "command.txt").write_text("test --source-scope <tree>\n", encoding="utf-8")
            (artifacts / "normalization.json").write_text(json.dumps({
                "sarif_results": 0,
                "without_case_id": 0,
                "without_cwe": 0,
                "normalized_findings": 0,
            }) + "\n", encoding="utf-8")
            (artifacts / "normalized.jsonl").write_text(
                json.dumps({
                    "schema_version": 1,
                    "case_id": "BenchmarkTest00001",
                    "cwes": ["CWE-22"],
                    "tool": "test",
                    "rule_id": "r",
                    "rule_name": None,
                    "level": "error",
                    "file_or_url": "app.py",
                    "line": 1,
                    "message": "test",
                    "raw_ref": "raw.sarif#0",
                }) + "\n",
                encoding="utf-8",
            )
            (artifacts / "score.json").write_text(json.dumps({
                "schema_version": 1,
                "matching_policy": "strict",
                "all_cases": metrics(),
                "diagnostics": {},
            }) + "\n", encoding="utf-8")
            rules = root / "frozen-rules.yml"
            rules.write_text("rules:\n  - id: test\n", encoding="utf-8")
            rules_digest = hashlib.sha256(rules.read_bytes()).hexdigest()
            (artifacts / "semgrep-provenance.json").write_text(
                json.dumps({"sha256": rules_digest, "publishable": False}) + "\n", encoding="utf-8"
            )
            create_manifest(
                artifacts,
                run_id="run-1",
                tool="test",
                method="sast",
                benchmark_commit=SHA,
                harness_commit=SHA,
                command=["test --source-scope <scope>"],
                status="PASS",
                exit_code=0,
                started_at="2026-09-16T00:00:00Z",
                tool_version="test 1",
                config={
                    "path": str(rules),
                    "sha256": "0" * 64,
                    "evidence_path": "semgrep-provenance.json",
                },
                source_scope=json.loads((scope / "source-scope.json").read_text()),
            )
            self.assertEqual(validate_run(artifacts), [])
            manifest_value = json.loads((artifacts / "manifest.json").read_text(encoding="utf-8"))
            environment_path = artifacts / "environment.json"
            self.assertTrue(environment_path.is_file())
            environment_value = json.loads(environment_path.read_text(encoding="utf-8"))
            self.assertEqual(environment_value, manifest_value["environment"])
            checksums = (artifacts / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("  environment.json\n", checksums)
            self.assertEqual(manifest_value["configuration"]["path"], "external:frozen-rules.yml")
            self.assertEqual(manifest_value["configuration"]["sha256"], rules_digest)
            self.assertNotIn("frozen-rules.yml", (artifacts / "SHA256SUMS").read_text(encoding="utf-8"))
            environment_value["architecture"] = "tampered"
            environment_path.write_text(json.dumps(environment_value), encoding="utf-8")
            self.assertTrue(validate_run(artifacts))
            # Recreate the manifest to refresh the standalone environment and
            # checksum evidence, then prove omission is rejected as well.
            create_manifest(
                artifacts,
                run_id="run-1",
                tool="test",
                method="sast",
                benchmark_commit=SHA,
                harness_commit=SHA,
                command=["test --source-scope <scope>"],
                status="PASS",
                exit_code=0,
                started_at="2026-09-16T00:00:00Z",
                tool_version="test 1",
                config={"path": str(rules), "sha256": "0" * 64, "evidence_path": "semgrep-provenance.json"},
                source_scope=json.loads((scope / "source-scope.json").read_text()),
            )
            environment_path.unlink()
            self.assertTrue(validate_run(artifacts))
            (artifacts / "raw.sarif").write_text("tampered\n", encoding="utf-8")
            self.assertTrue(validate_run(artifacts))
            verify = subprocess.run(
                [sys.executable, str(TOOLS / "run_manifest.py"), "verify", "--artifact-dir", str(artifacts)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(verify.returncode, 0)

    def test_zap_plan_and_history_require_single_seed_boundary(self):
        plan = Path(__file__).resolve().parents[1] / "configs" / "zap-automation.example.yaml"
        digest = "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
        self.assertEqual(validate_plan(plan, target_url="http://benchmark:8000/benchmark", image_digest=digest), [])
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.json"
            history.write_text(json.dumps({
                "seed_request_count": 2,
                "unique_case_ids": 2,
                "missing_case_ids": [],
                "duplicate_seed_requests": 0,
                "seed_boundary_recorded": True,
                "matched": [
                    {"case_id": "BenchmarkTest00001", "url": "http://benchmark:8000/benchmark/BenchmarkTest00001"},
                    {"case_id": "BenchmarkTest00002", "url": "http://benchmark:8000/benchmark/BenchmarkTest00002"},
                ],
            }), encoding="utf-8")
            self.assertEqual(validate_history(history, 2), [])
            history.write_text(history.read_text().replace("2", "1"), encoding="utf-8")
            self.assertTrue(validate_history(history, 2))

    def test_zap_execution_binds_arm64_child_digest_and_retains_index_provenance(self):
        root = Path(__file__).resolve().parents[1]
        compose = (root / "configs" / "zap-compose.example.yml").read_text(encoding="utf-8")
        integration = (root / "scripts" / "verify-zap-integration.sh").read_text(encoding="utf-8")
        topology = (root / "scripts" / "zap-topology.sh").read_text(encoding="utf-8")
        child = "sha256:05cbf4cab5d2fdaef55b0cd0b586f22d0ce4f75e0995f3cea2db23afbbdfd2f8"
        index = "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
        self.assertIn("platform: linux/arm64", compose)
        self.assertIn("@${ZAP_PLATFORM_DIGEST:?set immutable ZAP_PLATFORM_DIGEST}", compose)
        self.assertNotIn("@${ZAP_IMAGE_DIGEST", compose)
        self.assertIn(child, integration)
        self.assertIn(index, integration)
        self.assertIn('docker pull "$zap_image@$zap_platform_digest"', integration)
        self.assertIn('"$zap_image@$zap_platform_digest" zap.sh -version', integration)
        self.assertIn('ZAP_PLATFORM_DIGEST:?set immutable arm64 ZAP_PLATFORM_DIGEST', topology)

    def test_zap_seed_boundary_requires_complete_nonempty_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = root / "history.json"
            history.write_text(json.dumps({
                "seed_request_count": 1,
                "unique_case_ids": 1,
                "duplicate_seed_requests": 0,
                "missing_case_ids": [],
                "not_run_case_ids": [],
                "not_run_reasons": {},
                "matched": [{"case_id": "BenchmarkTest00001", "url": "http://benchmark:8000/benchmark/1"}],
            }), encoding="utf-8")
            boundary = root / "seed-boundary.json"
            value = make_boundary(history, boundary)
            self.assertTrue(boundary.stat().st_size > 0)
            self.assertEqual(value["seed_request_count"], 1)
            history.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                make_boundary(history, root / "empty-boundary.json")

    def test_zap_alert_mapping_canary_is_pinned_to_case_urls_and_cwes(self):
        canary = Path(__file__).resolve().parents[1] / "configs" / "zap-alert-mapping-canary.json"
        self.assertEqual(validate_alert_canary(canary), [])
        value = json.loads(canary.read_text(encoding="utf-8"))
        value["alerts"][0]["cwe"] = "not-a-cwe"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "canary.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertTrue(validate_alert_canary(path))

    def test_zap_coverage_requires_all_1230_unique_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            cases = [{
                "case_id": f"BenchmarkTest{index:05d}",
                "method": "GET",
                "url": f"http://benchmark:8000/benchmark/{index}",
                "input_names": [],
                "status": 200,
                "reached_target": True,
                "exercised": True,
                "error": None,
                "not_run_reason": None,
                "elapsed_ms": 1.0,
            } for index in range(1, 1231)]
            path.write_text(json.dumps({
                "planned": 1230,
                "executed": 1230,
                "failed": 0,
                "total": 1230,
                "exercised": 1230,
                "not_run": 0,
                "coverage_rate": 1.0,
                "cases": cases,
            }), encoding="utf-8")
            self.assertEqual(validate_coverage(path), [])
            cases[-1]["case_id"] = cases[-2]["case_id"]
            path.write_text(json.dumps({"planned": 1230, "cases": cases}), encoding="utf-8")
            self.assertTrue(validate_coverage(path))

    def test_zap_coverage_recomputes_counters_and_statuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            cases = [{
                "case_id": "BenchmarkTest00001",
                "method": "GET",
                "url": "http://benchmark:8000/benchmark/1",
                "input_names": [],
                "status": 200,
                "reached_target": True,
                "exercised": True,
                "error": None,
                "not_run_reason": None,
                "elapsed_ms": 1.0,
            }, {
                "case_id": "BenchmarkTest00002",
                "method": "GET",
                "url": "http://benchmark:8000/benchmark/2",
                "input_names": [],
                "status": None,
                "reached_target": False,
                "exercised": False,
                "error": "request construction: invalid header",
                "not_run_reason": "request construction: invalid header",
                "elapsed_ms": 1.0,
            }]
            # Use a small planned count so the adversarial arithmetic is easy to inspect.
            value = {
                "planned": 2,
                "executed": 1,
                "failed": 1,
                "total": 2,
                "exercised": 1,
                "not_run": 1,
                "coverage_rate": 0.5,
                "cases": cases,
            }
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(validate_coverage(path, planned=2), [])
            for field, bad in (("executed", 2), ("failed", 0), ("exercised", 2), ("not_run", 0), ("coverage_rate", 1.0)):
                tampered = dict(value)
                tampered[field] = bad
                path.write_text(json.dumps(tampered), encoding="utf-8")
                self.assertTrue(validate_coverage(path, planned=2), field)
            tampered = json.loads(json.dumps(value))
            tampered["cases"][0]["status"] = 500
            path.write_text(json.dumps(tampered), encoding="utf-8")
            self.assertTrue(validate_coverage(path, planned=2))
            tampered = json.loads(json.dumps(value))
            tampered["cases"][1]["not_run_reason"] = "different reason"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            self.assertTrue(validate_coverage(path, planned=2))

    def test_zap_history_allows_only_predeclared_not_run_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            coverage = root / "coverage.json"
            coverage.write_text(json.dumps({
                "planned": 5,
                "cases": [
                    {"case_id": "BenchmarkTest00001", "url": "http://benchmark:8000/benchmark/1", "exercised": True},
                    {"case_id": "BenchmarkTest00002", "url": "http://benchmark:8000/benchmark/2", "exercised": True},
                    {"case_id": "BenchmarkTest00003", "url": "http://benchmark:8000/benchmark/3", "exercised": True},
                    {"case_id": "BenchmarkTest00654", "url": None, "exercised": False, "not_run_reason": "header construction"},
                    {"case_id": "BenchmarkTest00658", "url": None, "exercised": False, "not_run_reason": "header construction"},
                ],
            }), encoding="utf-8")
            history = root / "history.json"
            history.write_text(json.dumps({
                "seed_request_count": 3,
                "unique_case_ids": 3,
                "missing_case_ids": ["BenchmarkTest00654", "BenchmarkTest00658"],
                "missing_exercised_case_ids": [],
                "not_run_case_ids": ["BenchmarkTest00654", "BenchmarkTest00658"],
                "not_run_reasons": {
                    "BenchmarkTest00654": "header construction",
                    "BenchmarkTest00658": "header construction",
                },
                "duplicate_seed_requests": 0,
                "seed_boundary_recorded": True,
                "matched": [
                    {"case_id": f"BenchmarkTest{index:05d}", "url": f"http://benchmark:8000/benchmark/{index}"}
                    for index in range(1, 4)
                ],
            }), encoding="utf-8")
            self.assertEqual(validate_history(history, 5, coverage), [])
            value = json.loads(history.read_text(encoding="utf-8"))
            value["matched"][0]["url"] = "http://benchmark:8000/benchmark/wrong"
            history.write_text(json.dumps(value), encoding="utf-8")
            self.assertTrue(validate_history(history, 5, coverage))
            value["matched"][0]["url"] = "http://benchmark:8000/benchmark/1"
            value["missing_case_ids"] = ["BenchmarkTest00004"]
            history.write_text(json.dumps(value), encoding="utf-8")
            self.assertTrue(validate_history(history, 5, coverage))

    def test_aggregate_keeps_each_run_and_reports_recurrence(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            run1 = release / "semgrep" / "run-1"
            run2 = release / "semgrep" / "run-2"
            for run in (run1, run2):
                run.mkdir(parents=True)
                (run / "manifest.json").write_text(json.dumps({"run_id": run.name, "tool": "semgrep", "method": "sast", "status": "PASS"}), encoding="utf-8")
                (run / "score.json").write_text(json.dumps({"all_cases": metrics()}), encoding="utf-8")
                (run / "normalized.jsonl").write_text(json.dumps({"case_id": "BenchmarkTest00001", "cwes": ["CWE-22"]}) + "\n", encoding="utf-8")
            result = aggregate(release)
            self.assertEqual(len(result["runs"]), 2)
            self.assertFalse(result["unioned_findings"])
            self.assertEqual(result["stability"]["semgrep"]["finding_set_recurrence"], 1)


if __name__ == "__main__":
    unittest.main()
