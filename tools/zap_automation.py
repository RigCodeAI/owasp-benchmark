#!/usr/bin/env python3
"""Validate ZAP Automation Framework plans and runtime boundary evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


KNOWN_UNUSUAL_NOT_RUN = {
    "BenchmarkTest00654",
    "BenchmarkTest00655",
    "BenchmarkTest00658",
    "BenchmarkTest00659",
    "BenchmarkTest00660",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_plan(path: Path, *, target_url: str | None = None, image_digest: str | None = None) -> list[str]:
    """Perform fail-closed checks without making a mutable YAML dependency mandatory."""
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "sendRequests: true" in text:
        errors.append("Automation plan imports HAR with sendRequests=true; seed traffic would run twice")
    if "sendRequests:" in text and "sendRequests: false" not in text:
        errors.append("Automation plan must not enable HAR request replay")
    if "type: passiveScan-wait" not in text:
        errors.append("Automation plan must wait for passive scanning")
    if "type: activeScan" not in text:
        errors.append("Automation plan must contain activeScan")
    if "template: traditional-json-plus" not in text or "template: sarif-json" not in text:
        errors.append("Automation plan must export traditional JSON and SARIF")
    if "seed_traffic: external-proxy-replay" not in text:
        errors.append("Automation plan must declare external proxy replay as its sole seed mechanism")
    digest_match = re.search(r"(?:imageDigest|digest|@)(?:\s*:\s*|\s*)(sha256:[0-9a-f]{64})", text, re.IGNORECASE)
    if image_digest is None:
        errors.append("pinned ZAP image digest is required")
    elif not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        errors.append("ZAP image digest must be sha256:<64 hex characters>")
    elif digest_match and digest_match.group(1) != image_digest:
        errors.append("Automation plan image digest differs from requested pinned digest")
    if target_url:
        urls = re.findall(r"https?://[^\s'\"]+", text)
        if not any(url.rstrip("/") == target_url.rstrip("/") for url in urls):
            errors.append(f"Automation plan has no context/active-scan URL matching {target_url}")
    return errors


def validate_history(path: Path, planned: int, coverage_path: Path | None = None) -> list[str]:
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid ZAP history evidence: {exc}"]
    if not isinstance(value, dict):
        return ["ZAP history evidence must be a JSON object"]
    errors: list[str] = []
    expected_not_run: dict[str, str | None] = {}
    expected_exercised: set[str] = set()
    expected_urls: dict[str, str] = {}
    if coverage_path is not None:
        try:
            coverage: Any = json.loads(coverage_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [f"invalid coverage evidence for history validation: {exc}"]
        cases = coverage.get("cases") if isinstance(coverage, dict) else None
        if not isinstance(cases, list):
            return ["coverage evidence has no cases for history validation"]
        for item in cases:
            if not isinstance(item, dict):
                errors.append("coverage contains a malformed case record")
                continue
            identifier = item.get("case_id")
            if item.get("exercised"):
                if isinstance(identifier, str):
                    expected_exercised.add(identifier)
                    url = item.get("url")
                    if isinstance(url, str) and url:
                        expected_urls[identifier] = url
            else:
                if isinstance(identifier, str):
                    expected_not_run[identifier] = item.get("not_run_reason")
        if set(expected_not_run) - KNOWN_UNUSUAL_NOT_RUN:
            errors.append("coverage marks a non-predeclared case not_run")
    else:
        expected_exercised = {
            item.get("case_id") for item in value.get("matched", []) if isinstance(item, dict)
        }
        if len(expected_exercised) != planned:
            expected_exercised = {f"BenchmarkTest{index:05d}" for index in range(1, planned + 1)}
    expected_count = len(expected_exercised)
    if value.get("seed_request_count") != expected_count:
        errors.append("ZAP history seed request count does not equal exercised requests")
    if value.get("unique_case_ids") != expected_count:
        errors.append("ZAP history does not contain every unique exercised case ID")
    missing_values = value.get("missing_case_ids") or []
    if not isinstance(missing_values, list) or any(not isinstance(item, str) for item in missing_values):
        errors.append("ZAP history missing_case_ids must be a list of case IDs")
        missing_values = []
    missing = set(missing_values)
    if coverage_path is None:
        if missing:
            errors.append("ZAP history has missing seeded case IDs")
    elif missing != set(expected_not_run):
        errors.append("ZAP history missing IDs do not equal coverage not_run records")
    if coverage_path is not None:
        not_run_values = value.get("not_run_case_ids") or []
        if not isinstance(not_run_values, list) or any(not isinstance(item, str) for item in not_run_values):
            errors.append("ZAP history not_run_case_ids must be a list of case IDs")
            not_run_values = []
        if set(not_run_values) != set(expected_not_run):
            errors.append("ZAP history not_run IDs do not equal coverage")
        missing_exercised_values = value.get("missing_exercised_case_ids") or []
        if not isinstance(missing_exercised_values, list) or any(not isinstance(item, str) for item in missing_exercised_values):
            errors.append("ZAP history missing_exercised_case_ids must be a list of case IDs")
            missing_exercised_values = []
        if set(missing_exercised_values) != set(expected_exercised) - {
            item.get("case_id") for item in value.get("matched", []) if isinstance(item, dict)
        }:
            errors.append("ZAP history exercised missing IDs do not match matched evidence")
        reasons = value.get("not_run_reasons")
        if reasons != expected_not_run:
            errors.append("ZAP history not_run reasons do not match coverage")
    if value.get("duplicate_seed_requests", 0) != 0:
        errors.append("ZAP history shows duplicate seed requests")
    if not value.get("seed_boundary_recorded", False):
        errors.append("ZAP seed boundary is not recorded")
    matched = value.get("matched")
    if not isinstance(matched, list) or len(matched) != expected_count:
        errors.append("ZAP history must retain one matched evidence record per exercised case")
    else:
        identifiers = [item.get("case_id") for item in matched if isinstance(item, dict)]
        if any(not isinstance(identifier, str) for identifier in identifiers):
            errors.append("ZAP history matched evidence contains an invalid case ID")
        if (
            len(identifiers) != expected_count
            or len([identifier for identifier in identifiers if isinstance(identifier, str)]) != expected_count
            or len(set(identifier for identifier in identifiers if isinstance(identifier, str))) != expected_count
            or set(identifier for identifier in identifiers if isinstance(identifier, str)) != expected_exercised
        ):
            errors.append("ZAP history matched evidence does not contain unique case IDs")
        if any(not isinstance(item, dict) or not isinstance(item.get("url"), str) or not item.get("url") for item in matched):
            errors.append("ZAP history matched evidence lacks exact request URLs")
        if coverage_path is not None:
            for item in matched:
                if not isinstance(item, dict):
                    continue
                identifier = item.get("case_id")
                url = item.get("url")
                expected_url = expected_urls.get(identifier) if isinstance(identifier, str) else None
                if expected_url is None or url != expected_url:
                    errors.append(f"ZAP history URL for {identifier!r} does not exactly match coverage URL")
    return errors


def validate_coverage(path: Path, planned: int = 1230) -> list[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid coverage evidence: {exc}"]
    if not isinstance(value, dict):
        return ["coverage evidence must be a JSON object"]
    cases = value.get("cases")
    errors: list[str] = []
    if value.get("planned") != planned:
        errors.append(f"coverage planned must be {planned}")
    if not isinstance(cases, list) or len(cases) != planned:
        errors.append(f"coverage must retain exactly {planned} case records")
        return errors
    identifiers = [item.get("case_id") for item in cases if isinstance(item, dict)]
    expected = {f"BenchmarkTest{index:05d}" for index in range(1, planned + 1)}
    valid_identifiers = [identifier for identifier in identifiers if isinstance(identifier, str)]
    if len(valid_identifiers) != planned or len(set(valid_identifiers)) != planned:
        errors.append("coverage case IDs are not unique")
    if set(valid_identifiers) != expected:
        errors.append("coverage case IDs are not exactly BenchmarkTest00001..BenchmarkTest01230")

    exercised_count = 0
    not_run_count = 0
    for index, item in enumerate(cases):
        if not isinstance(item, dict):
            errors.append(f"coverage case {index} must be an object")
            not_run_count += 1
            continue
        exercised = item.get("exercised")
        if type(exercised) is not bool:
            errors.append(f"coverage case {index} exercised must be boolean")
            continue
        reached_target = item.get("reached_target")
        if type(reached_target) is not bool:
            errors.append(f"coverage case {index} reached_target must be boolean")
        status = item.get("status")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            errors.append(f"coverage case {index} status must be an HTTP status or null")
        error = item.get("error")
        if error is not None and not isinstance(error, str):
            errors.append(f"coverage case {index} error must be a string or null")
        not_run_reason = item.get("not_run_reason")
        if not_run_reason is not None and not isinstance(not_run_reason, str):
            errors.append(f"coverage case {index} not_run_reason must be a string or null")
        if exercised:
            exercised_count += 1
            if reached_target is not True:
                errors.append(f"coverage case {index} is exercised without reaching the target")
            if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status < 400:
                errors.append(f"coverage case {index} is exercised without a successful HTTP status")
            if error is not None or not_run_reason is not None:
                errors.append(f"coverage case {index} is exercised but records an error/not_run reason")
            if not isinstance(item.get("url"), str) or not item.get("url"):
                errors.append(f"coverage case {index} is exercised without a request URL")
        else:
            not_run_count += 1
            if not isinstance(not_run_reason, str) or not not_run_reason:
                errors.append(f"coverage case {index} not_run record lacks a reason")
            if isinstance(error, str) and error and not_run_reason != error:
                errors.append(f"coverage case {index} not_run reason does not match error")
            if isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 400:
                errors.append(f"coverage case {index} is not exercised despite a successful HTTP status")
            if reached_target is True and status is None:
                errors.append(f"coverage case {index} reached the target without an HTTP status")

    expected_counters = {
        "executed": exercised_count,
        "failed": not_run_count,
        "total": planned,
        "exercised": exercised_count,
        "not_run": not_run_count,
    }
    for name, expected_value in expected_counters.items():
        actual = value.get(name)
        if type(actual) is not int or actual != expected_value:
            errors.append(f"coverage {name} does not match case statuses")
    expected_rate = round(exercised_count / planned, 6) if planned else None
    actual_rate = value.get("coverage_rate")
    if actual_rate != expected_rate or (actual_rate is not None and (type(actual_rate) not in (int, float) or isinstance(actual_rate, bool))):
        errors.append("coverage_rate does not match exercised case statuses")
    return errors


def validate_alert_canary(path: Path, target_url: str = "http://benchmark:8000/benchmark") -> list[str]:
    """Validate the checked-in alert-to-case/CWE mapping canary inputs.

    This is intentionally independent of a live ZAP session.  It catches a
    changed case URL, duplicate case, or malformed CWE before a report can be
    interpreted as benchmark evidence.
    """
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid ZAP alert canary: {exc}"]
    errors: list[str] = []
    entries = value.get("alerts") if isinstance(value, dict) else None
    if not isinstance(entries, list) or not entries:
        return ["ZAP alert canary must contain a non-empty alerts array"]
    identifiers: list[str] = []
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            errors.append(f"alert canary entry {index} must be an object")
            continue
        identifier = item.get("case_id")
        cwe = item.get("cwe")
        url = item.get("url")
        if not isinstance(identifier, str) or not re.fullmatch(r"BenchmarkTest[0-9]{5}", identifier):
            errors.append(f"alert canary entry {index} has invalid case_id")
        else:
            identifiers.append(identifier)
        if not isinstance(cwe, str) or not re.fullmatch(r"CWE-[0-9]+", cwe):
            errors.append(f"alert canary entry {index} has invalid CWE")
        if not isinstance(url, str) or not url.startswith(target_url.rstrip("/") + "/"):
            errors.append(f"alert canary entry {index} is outside the pinned target URL")
    if len(identifiers) != len(set(identifiers)):
        errors.append("alert canary contains duplicate case IDs")
    return errors


def runtime_record(
    artifact_dir: Path,
    *,
    image: str,
    digest: str,
    version: Any,
    addons: Any,
    plan: Path,
    platform_digest: str | None = None,
) -> dict:
    record = {
        "schema_version": 1,
        "image": image,
        "image_digest": digest,
        "platform_digest": platform_digest or digest,
        "version": version,
        "addons": addons,
        "addons_sha256": hashlib.sha256(json.dumps(addons, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
        "automation_plan": plan.name,
        "automation_plan_sha256": sha256(plan),
    }
    output = artifact_dir / "zap-runtime.json"
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def make_boundary(history: Path, output: Path) -> dict[str, Any]:
    """Copy only complete, non-empty seed boundary evidence."""
    try:
        value = json.loads(history.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid ZAP history evidence: {exc}") from exc
    if not isinstance(value, dict) or not value:
        raise ValueError("ZAP history evidence is empty")
    required = (
        "seed_request_count",
        "unique_case_ids",
        "duplicate_seed_requests",
        "missing_case_ids",
        "not_run_case_ids",
        "not_run_reasons",
        "matched",
    )
    if any(key not in value for key in required):
        raise ValueError("ZAP history evidence lacks seed boundary fields")
    boundary = {
        "schema_version": 1,
        "seed_request_count": value["seed_request_count"],
        "unique_case_ids": value["unique_case_ids"],
        "duplicate_seed_requests": value["duplicate_seed_requests"],
        "missing_case_ids": value.get("missing_case_ids", []),
        "not_run_case_ids": value.get("not_run_case_ids", []),
        "not_run_reasons": value.get("not_run_reasons", {}),
        "history_artifact": history.name,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(boundary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if output.stat().st_size == 0:
        raise ValueError("seed-boundary.json is empty")
    return boundary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    plan = sub.add_parser("validate-plan")
    plan.add_argument("--plan", type=Path, required=True)
    plan.add_argument("--target-url")
    plan.add_argument("--image-digest")
    history = sub.add_parser("validate-history")
    history.add_argument("--history", type=Path, required=True)
    history.add_argument("--planned", type=int, required=True)
    history.add_argument("--coverage", type=Path)
    coverage = sub.add_parser("validate-coverage")
    coverage.add_argument("--coverage", type=Path, required=True)
    coverage.add_argument("--planned", type=int, default=1230)
    canary = sub.add_parser("validate-alert-canary")
    canary.add_argument("--canary", type=Path, required=True)
    canary.add_argument("--target-url", default="http://benchmark:8000/benchmark")
    boundary = sub.add_parser("make-boundary")
    boundary.add_argument("--history", type=Path, required=True)
    boundary.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "validate-plan":
        errors = validate_plan(args.plan, target_url=args.target_url, image_digest=args.image_digest)
    elif args.action == "validate-history":
        errors = validate_history(args.history, args.planned, args.coverage)
    elif args.action == "validate-coverage":
        errors = validate_coverage(args.coverage, args.planned)
    elif args.action == "validate-alert-canary":
        errors = validate_alert_canary(args.canary, args.target_url)
    else:
        try:
            make_boundary(args.history, args.output)
            errors = []
        except (OSError, ValueError) as exc:
            errors = [str(exc)]
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("ZAP evidence validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
