#!/usr/bin/env python3
"""CI checks for Phase 0 guarantees that do not require scanner binaries."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from zap_automation import validate_alert_canary, validate_plan


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    errors: list[str] = []
    for schema in sorted((ROOT / "schemas").glob("*.json")):
        try:
            value = json.loads(schema.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or "$schema" not in value:
                errors.append(f"invalid schema envelope: {schema}")
        except json.JSONDecodeError as exc:
            errors.append(f"invalid schema JSON {schema}: {exc}")
    plan = ROOT / "configs" / "zap-automation.example.yaml"
    digest = "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
    errors.extend(validate_plan(plan, target_url="http://benchmark:8000/benchmark", image_digest=digest))
    errors.extend(validate_alert_canary(ROOT / "configs" / "zap-alert-mapping-canary.json"))
    codeql = json.loads((ROOT / "configs" / "vendors" / "codeql.json").read_text(encoding="utf-8"))
    if codeql.get("bundle_archive_sha256") != "84e5f9d804ae58c41930c33cd61cbeffdbca86689fc85f2f89a2ab0eec433bd6":
        errors.append("CodeQL bundle archive checksum is not release-frozen")
    if codeql.get("cli_version") != "2.27.0" or codeql.get("query_pack_version") != "1.8.10" or codeql.get("resolve_command") != "codeql resolve packs":
        errors.append("CodeQL query-pack resolution metadata is not release-frozen")
    codeql_runner = (ROOT / "scripts" / "run" / "codeql.sh").read_text(encoding="utf-8")
    if (
        "codeql-suites/python-security-extended.qls" not in codeql_runner
        or "qlpacks/codeql/python-queries/$query_pack_version" not in codeql_runner
        or 'suite="$query_pack/codeql-suites/python-security-extended.qls"' not in codeql_runner
    ):
        errors.append("CodeQL runner does not resolve the installed pinned suite and query pack")
    semgrep = json.loads((ROOT / "configs" / "vendors" / "semgrep.json").read_text(encoding="utf-8"))
    snapshot = semgrep.get("resolved_snapshot", {})
    if (
        snapshot.get("publishable") is not False
        or snapshot.get("redistribution") != "prohibited"
        or snapshot.get("redistribution_allowed") is not False
        or snapshot.get("license") != {
            "id": "Semgrep Rules License v1.0",
            "url": "https://semgrep.dev/legal/rules-license/",
        }
        or snapshot.get("source_url") != "https://semgrep.dev/c/p/python"
        or snapshot.get("source_ref") != "p/python"
        or snapshot.get("cli_mode") != "community"
        or snapshot.get("account_status") != "unauthenticated"
        or snapshot.get("auth_status") != "not_applicable"
        or snapshot.get("sha256") != "31c1dfa46e8ddd97f9ac98c607ddd77b20a2c3356d7ec987359961d47ec27035"
        or snapshot.get("rules") != 151
    ):
        errors.append("Semgrep frozen snapshot metadata is not release-frozen")
    snyk = json.loads((ROOT / "configs" / "vendors" / "snyk.json").read_text(encoding="utf-8"))
    if (
        snyk.get("cli_version") != "1.1306.3"
        or snyk.get("official_cli_version") != "1.1306.3"
        or snyk.get("binary_sha256") != "6affd215ef52f0eebaddd34e946c64bc8cfb06223387d8e6164a10501910fa92"
        or snyk.get("requires_absolute_binary") is not True
        or snyk.get("requires_external_cache") is not True
        or snyk.get("requires_written_consent") is not True
    ):
        errors.append("Snyk CLI provenance pins are not release-frozen")
    zap_vendor = json.loads((ROOT / "configs" / "vendors" / "zap.json").read_text(encoding="utf-8"))
    if zap_vendor.get("image_digest") != digest or zap_vendor.get("arm64_child_digest") != "sha256:05cbf4cab5d2fdaef55b0cd0b586f22d0ce4f75e0995f3cea2db23afbbdfd2f8":
        errors.append("ZAP image digests are not release-frozen")
    benchmark_image = json.loads((ROOT / "configs" / "benchmark-image.json").read_text(encoding="utf-8"))
    if benchmark_image.get("base_image_index_digest") != "sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea" or benchmark_image.get("base_image_platform_digest") != "sha256:3949e4271b0a3ff82afac7306764c313dcc8edeeb89c0376a3c2ac6007c66b1d":
        errors.append("Benchmark base image is not release-pinned")
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for marker in ("codeql-db", "codeql-state", "zap-session", "source-scope"):
        if marker not in ignore:
            errors.append(f".gitignore does not exclude {marker}")
    topology = (ROOT / "configs" / "zap-compose.example.yml").read_text(encoding="utf-8")
    if "ports:" in topology or "internal: true" not in topology:
        errors.append("ZAP topology must be private and publish no host ports")
    if topology.count("platform: linux/arm64") != 2:
        errors.append("both benchmark and ZAP Compose services must be pinned to linux/arm64")
    if "${ZAP_PLATFORM_DIGEST:?set immutable ZAP_PLATFORM_DIGEST}" not in topology:
        errors.append("Compose must execute ZAP by the frozen linux/arm64 child digest")
    if "@${ZAP_IMAGE_DIGEST" in topology:
        errors.append("Compose must not execute ZAP by the multi-architecture index digest")
    if "mem_limit:" not in topology or "cpus:" not in topology or "pids_limit:" not in topology:
        errors.append("ZAP topology is missing resource limits")
    if "app:app" not in topology or "FLASK_DEBUG: \"0\"" not in topology:
        errors.append("Benchmark topology is not an app:app production process")
    for required in ("TRAFFIC_TOOL_PATH", "CRAWLER_XML_PATH", "ZAP_PLAN_PATH"):
        if required not in topology:
            errors.append(f"ZAP topology does not mount exact {required}")
    for required in ("/zap/wrk/artifacts", "/home/zap/.ZAP", "/home/zap/.java", "/app/testfiles"):
        if required not in topology:
            errors.append(f"ZAP topology lacks writable state mount {required}")
    if "/benchmark/Index.html" not in topology:
        errors.append("Benchmark healthcheck must use the real Index.html route")
    dockerfile = (ROOT / "configs" / "benchmark.Dockerfile").read_text(encoding="utf-8")
    if "@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea" not in dockerfile or "chown -R 65532:65532 /app/testfiles" not in dockerfile:
        errors.append("Benchmark Dockerfile lacks immutable base or testfiles ownership")
    zap_runner = (ROOT / "scripts" / "run" / "zap.sh").read_text(encoding="utf-8")
    if "ZAP_AUTOMATION_CMD" in zap_runner or "trap cleanup EXIT" not in zap_runner:
        errors.append("ZAP runner accepts arbitrary automation or lacks cleanup trap")
    for marker in ("--plan /zap/wrk/zap-plan.yaml", "--project", "--target http://benchmark:8000/benchmark"):
        if marker not in zap_runner:
            errors.append(f"ZAP runtime metadata is not tied to {marker}")
    topology_script = (ROOT / "scripts" / "zap-topology.sh").read_text(encoding="utf-8")
    if "prepare|up|down" not in topology_script or "--force-recreate" not in topology_script or "down --volumes --remove-orphans" not in topology_script:
        errors.append("topology lifecycle does not expose prepare, fresh start, and cleanup")
    up_start = topology_script.find('if [ "$1" = up ]; then')
    up_end = topology_script.find("\nfi", up_start) if up_start >= 0 else -1
    if up_start < 0 or up_end < 0 or "down --volumes" in topology_script[up_start:up_end]:
        errors.append("topology up must preserve volumes initialized by prepare")
    for runner in ("scripts/run/zap.sh", "scripts/verify-zap-integration.sh"):
        runner_text = (ROOT / runner).read_text(encoding="utf-8")
        prepare_marker = "scripts/zap-topology.sh\" prepare"
        if prepare_marker not in runner_text:
            errors.append(f"{runner} does not initialize topology ownership before preflight")
        elif runner_text.find(prepare_marker) > runner_text.find("$compose run"):
            errors.append(f"{runner} runs a Compose preflight before topology preparation")
    for marker in ("run --rm --no-deps", "--user 0:0", "--cap-drop ALL", "--cap-add CHOWN", "chown -R 1000:1000 /zap/wrk/artifacts /home/zap/.ZAP /home/zap/.java", "ZAP_PLATFORM_DIGEST"):
        if marker not in topology_script:
            errors.append(f"topology startup lacks constrained writable-volume initialization: {marker}")
    export_script = ROOT / "scripts" / "zap-export-artifacts.sh"
    if not export_script.is_file() or "docker compose" not in export_script.read_text(encoding="utf-8") or "/zap/wrk/artifacts/." not in export_script.read_text(encoding="utf-8"):
        errors.append("ZAP named artifact volume lacks a checked export helper")
    for runner in ("semgrep.sh", "snyk.sh", "codeql.sh", "zap.sh"):
        runner_text = (ROOT / "scripts" / "run" / runner).read_text(encoding="utf-8")
        if "validate_sarif.py" not in runner_text:
            errors.append(f"{runner} does not validate SARIF structurally")
    snyk_runner = (ROOT / "scripts" / "run" / "snyk.sh").read_text(encoding="utf-8")
    for marker in ("SNYK_BIN", "SNYK_CACHE_PATH", "SNYK_WRITTEN_CONSENT", "whoami --json", "snyk_provenance.py", "--config-path snyk-provenance.json"):
        if marker not in snyk_runner:
            errors.append(f"Snyk runner lacks provenance boundary: {marker}")
    if "snyk config" in snyk_runner or "whoami --json >" not in snyk_runner or "2>/dev/null" not in snyk_runner:
        errors.append("Snyk runner exposes raw identity/configuration output")
    provenance_schema = ROOT / "schemas" / "snyk-provenance.schema.json"
    if not provenance_schema.is_file():
        errors.append("Snyk provenance schema is missing")
    manifest_tool = (ROOT / "tools" / "run_manifest.py").read_text(encoding="utf-8")
    if (
        "validate_snyk_provenance" not in manifest_tool
        or "validate_snyk_artifacts" not in manifest_tool
        or "require_ready=status == \"PASS\"" not in manifest_tool
        or "snyk-provenance.json" not in manifest_tool
    ):
        errors.append("run manifest does not enforce Snyk provenance binding")
    traffic = (ROOT / "tools" / "traffic.py").read_text(encoding="utf-8")
    if "inScopeOnly" not in traffic or "/JSON/reports/action/generate/" not in traffic:
        errors.append("ZAP API operations lack exact scope/report endpoints")
    if "/OTHER/core/other/" in traffic or "inscopeonly" in traffic:
        errors.append("ZAP runner uses deprecated report API or incorrect inScopeOnly casing")
    if "zap_context" not in traffic or "ZapApiError" not in traffic:
        errors.append("ZAP API errors/context scope are not fail-closed")
    zap_plan = (ROOT / "configs" / "zap-automation.example.yaml").read_text(encoding="utf-8")
    if zap_plan.count("reportDir: /zap/wrk/artifacts") != 2:
        errors.append("ZAP Automation Framework reports must use /zap/wrk/artifacts")
    for runner in ("semgrep.sh", "snyk.sh", "codeql.sh"):
        runner_text = (ROOT / "scripts" / "run" / runner).read_text(encoding="utf-8")
        if "scope_dir/tree" not in runner_text:
            errors.append(f"{runner} does not scan only source-scope/tree")
    integration = (ROOT / "scripts" / "verify-zap-integration.sh").read_text(encoding="utf-8")
    for marker in (
        "docker pull",
        "zap.sh -version",
        "-autocheck /zap/wrk/zap-plan.yaml",
        "benchmark/Index.html",
        ".phase0-write-smoke",
        "zap-export-artifacts.sh",
        "docker build --platform linux/arm64",
        "docker run --rm --platform linux/arm64",
        "docker pull \"$zap_image@$zap_platform_digest\"",
        "\"$zap_image@$zap_platform_digest\" zap.sh -version",
        "ZAP_PLATFORM_DIGEST=\"$zap_platform_digest\"",
    ):
        if marker not in integration:
            errors.append(f"ZAP integration check lacks {marker}")
    workflow = (ROOT / ".github" / "workflows" / "verify.yml").read_text(encoding="utf-8")
    if "docker/setup-qemu-action@v3" not in workflow or "docker/setup-buildx-action@v3" not in workflow:
        errors.append("Docker Phase 0 job must configure QEMU and Buildx before arm64 checks")
    docker_job = workflow.split("phase0-docker:", 1)[-1]
    if docker_job.find("docker/setup-qemu-action@v3") > docker_job.find("Verify pinned ZAP topology"):
        errors.append("QEMU setup must precede the required Docker topology gate")
    for script in sorted((ROOT / "scripts").rglob("*.sh")):
        result = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True, check=False)
        if result.returncode:
            errors.append(f"shell syntax failed: {script}: {result.stderr.strip()}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Phase 0 harness checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
