#!/usr/bin/env python3
"""Build or replay deterministic HTTP traffic from BenchmarkPython's crawler XML."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

KNOWN_UNUSUAL_HEADER_CASES = {
    "BenchmarkTest00654": "header name is a URL and may be rejected by standards-compliant clients",
    "BenchmarkTest00655": "header name is a URL and may be rejected by standards-compliant clients",
    "BenchmarkTest00658": "header name contains a newline and may be rejected by standards-compliant clients",
    "BenchmarkTest00659": "header name contains a newline and may be rejected by standards-compliant clients",
    "BenchmarkTest00660": "header name contains a newline and may be rejected by standards-compliant clients",
}
ZAP_CASE_RE = re.compile(r"BenchmarkTest\d{5}")


class ZapApiError(RuntimeError):
    """Raised when the ZAP daemon returns an API or report-generation error."""


def case_id(value: object) -> str | None:
    match = re.search(r"BenchmarkTest(\d{1,5})", str(value), re.IGNORECASE)
    return f"BenchmarkTest{int(match.group(1)):05d}" if match else None


def parse_crawler(path: Path) -> list[dict]:
    root = ET.parse(path).getroot()
    cases: list[dict] = []
    for element in root.findall("benchmarkTest"):
        identifier = case_id(element.get("tcName", ""))
        if identifier is None:
            raise ValueError("crawler entry is missing a valid tcName")
        request = {
            "case_id": identifier,
            "source_url": element.get("URL"),
            "method": "POST" if element.findall("formparam") else "GET",
            "query": {},
            "form": {},
            "headers": {},
            "cookies": {},
        }
        mapping = {"getparam": "query", "formparam": "form", "header": "headers", "cookie": "cookies"}
        for xml_name, field in mapping.items():
            for child in element.findall(xml_name):
                name = child.get("name")
                if name is not None:
                    request[field][name] = child.get("value", "")
        cases.append(request)
    if not cases:
        raise ValueError("crawler XML contained no benchmarkTest entries")
    return cases


def target_url(source_url: str, base_url: str, query: dict[str, str]) -> str:
    source = urllib.parse.urlsplit(source_url)
    base = urllib.parse.urlsplit(base_url)
    if not base.scheme or not base.netloc:
        raise ValueError("base URL must include scheme and host")
    base_path = base.path.rstrip("/")
    path = source.path
    if base_path and path.startswith("/benchmark/") and base_path.endswith("/benchmark"):
        path = path[len("/benchmark") :]
    combined_path = base_path + path if base_path else path
    return urllib.parse.urlunsplit((base.scheme, base.netloc, combined_path, urllib.parse.urlencode(query), ""))


def require_local_target(base_url: str, allow_remote: bool) -> None:
    if allow_remote:
        return
    host = urllib.parse.urlsplit(base_url).hostname
    if not host:
        raise ValueError("base URL must include a host")
    if host.lower() == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError(
        f"refusing non-loopback target {host!r}; use --allow-remote only for an isolated benchmark host"
    )


def make_opener(proxy: str | None, insecure: bool) -> urllib.request.OpenerDirector:
    handlers: list = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))  # noqa: S323 - explicit CLI choice for local benchmark
    return urllib.request.build_opener(*handlers)


def replay(
    cases: list[dict], base_url: str, proxy: str | None, timeout: float, insecure: bool, allow_remote: bool = False
) -> dict:
    require_local_target(base_url, allow_remote)
    opener = make_opener(proxy, insecure)
    results: list[dict] = []
    for case in cases:
        url = None
        started = time.monotonic()
        status = None
        error = None
        exercised = False
        reached_target = False
        construction_error = None
        try:
            try:
                url = target_url(case["source_url"], base_url, case["query"])
                body = urllib.parse.urlencode(case["form"]).encode() if case["method"] == "POST" else None
                headers = {str(key): str(value) for key, value in case["headers"].items()}
                headers["User-Agent"] = "owasp-benchmark/1"
                if case["cookies"]:
                    headers["Cookie"] = "; ".join(
                        f"{key}={urllib.parse.quote_plus(value).replace('+', '%20')}"
                        for key, value in case["cookies"].items()
                    )
                if body is not None:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                request = urllib.request.Request(url, data=body, headers=headers, method=case["method"])
            except (TypeError, ValueError, UnicodeError, KeyError) as exc:
                construction_error = f"request construction: {exc}"
            if construction_error is None:
                with opener.open(request, timeout=timeout) as response:
                    status = response.status
                    response.read(1024)
                    reached_target = True
                    exercised = 200 <= status < 400
        except urllib.error.HTTPError as exc:
            status = exc.code
            reached_target = True
            error = f"HTTP {exc.code}"
        # urllib may defer header/cookie validation until the request is sent;
        # keep those malformed cases as explicit not_run records instead of
        # aborting the 1,230-case replay.
        except (urllib.error.URLError, TimeoutError, OSError, TypeError, ValueError, UnicodeError, KeyError) as exc:
            error = str(exc)
        if construction_error is not None:
            error = construction_error
        predeclared_reason = KNOWN_UNUSUAL_HEADER_CASES.get(case["case_id"])
        not_run_reason = None if exercised else (error or "request did not receive a successful response")
        results.append(
            {
                "case_id": case["case_id"],
                "method": case["method"],
                "url": url,
                "input_names": sorted(
                    set(case["query"]) | set(case["form"]) | set(case["headers"]) | set(case["cookies"])
                ),
                "status": status,
                "reached_target": reached_target,
                "exercised": exercised,
                "error": error,
                "predeclared_reason": predeclared_reason,
                "not_run_reason": not_run_reason,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            }
        )
    exercised_count = sum(1 for item in results if item["exercised"])
    method_counts = {method: sum(1 for item in cases if item["method"] == method) for method in ("GET", "POST")}
    return {
        "schema_version": 1,
        "base_url": base_url,
        "proxy": proxy,
        "planned": len(results),
        "executed": exercised_count,
        "failed": len(results) - exercised_count,
        "method_counts": method_counts,
        "total": len(results),
        "exercised": exercised_count,
        "not_run": len(results) - exercised_count,
        "coverage_rate": round(exercised_count / len(results), 6) if results else None,
        "cases": results,
    }


def build_har(cases: list[dict], base_url: str, allow_remote: bool = False) -> dict:
    """Create a deterministic HAR that ZAP can import and send."""
    require_local_target(base_url, allow_remote)
    entries = []
    for case in cases:
        url = target_url(case["source_url"], base_url, case["query"])
        headers = [{"name": str(key), "value": str(value)} for key, value in case["headers"].items()]
        headers.append({"name": "Content-Type", "value": "application/x-www-form-urlencoded"})
        if case["cookies"]:
            cookie_value = "; ".join(
                f"{key}={urllib.parse.quote_plus(value).replace('+', '%20')}"
                for key, value in case["cookies"].items()
            )
            headers.append({"name": "Cookie", "value": cookie_value})
        request = {
            "method": case["method"],
            "url": url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": headers,
            "queryString": [{"name": key, "value": value} for key, value in case["query"].items()],
            "headersSize": -1,
            "bodySize": -1,
        }
        if case["method"] == "POST":
            request["postData"] = {
                "mimeType": "application/x-www-form-urlencoded",
                "params": [{"name": key, "value": value} for key, value in case["form"].items()],
                "text": urllib.parse.urlencode(case["form"]),
            }
        entries.append(
            {
                "startedDateTime": "1970-01-01T00:00:00.000Z",
                "time": 0,
                "request": request,
                "response": {
                    "status": 0,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "content": {"size": 0, "mimeType": ""},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
                "comment": case["case_id"],
            }
        )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "owasp-benchmark", "version": "1"},
            "entries": entries,
        }
    }


def zap_api(base: str, endpoint: str, **params):
    query = urllib.parse.urlencode({key: value for key, value in params.items() if value is not None})
    url = f"{base.rstrip('/')}/{endpoint.lstrip('/')}" + (("?" + query) if query else "")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - private compose daemon only
            payload = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise ZapApiError(f"ZAP API request failed: {endpoint}: {exc}") from exc
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        return payload
    if isinstance(value, dict):
        code = value.get("code")
        if "error" in value or (code is not None and code not in (0, "0", "OK", "ok")):
            raise ZapApiError(f"ZAP API error from {endpoint}: {value}")
    return value


def _history_message_url(message: dict) -> str:
    if isinstance(message.get("url"), str):
        return message["url"]
    lines = str(message.get("requestHeader", "")).splitlines()
    match = re.match(r"\S+\s+(\S+)", lines[0]) if lines else None
    return match.group(1) if match else ""


def zap_history(base: str, coverage_path: Path, output: Path) -> dict:
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    expected = {item["case_id"]: item["url"] for item in coverage["cases"] if item.get("exercised")}
    not_run = {
        item["case_id"]: item.get("not_run_reason")
        for item in coverage["cases"]
        if not item.get("exercised")
    }
    response = zap_api(base, "/JSON/core/view/messages/", baseurl="http://benchmark:8000/benchmark", count=2000)
    messages = response.get("messages", []) if isinstance(response, dict) else []
    counts = {identifier: 0 for identifier in expected}
    matched = []
    for message in messages:
        url = _history_message_url(message)
        for identifier in ZAP_CASE_RE.findall(url):
            if identifier in counts and url == expected[identifier]:
                counts[identifier] += 1
                matched.append({"case_id": identifier, "url": url, "message_id": message.get("id")})
    matched_ids = {item["case_id"] for item in matched}
    missing = sorted(set(expected) - matched_ids)
    missing_not_run = sorted(not_run)
    evidence = {
        "schema_version": 1,
        "seed_request_count": len(matched),
        "unique_case_ids": sum(count == 1 for count in counts.values()),
        "duplicate_seed_requests": sum(max(count - 1, 0) for count in counts.values()),
        "missing_case_ids": missing + missing_not_run,
        "missing_exercised_case_ids": missing,
        "not_run_case_ids": missing_not_run,
        "not_run_reasons": not_run,
        "seed_boundary_recorded": True,
        "matched": matched,
    }
    write_json(output, evidence)
    return evidence


def zap_passive(base: str, output: Path, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    remaining = -1
    while time.monotonic() < deadline:
        response = zap_api(base, "/JSON/pscan/view/recordsToScan/")
        remaining = int(response.get("recordsToScan", -1)) if isinstance(response, dict) else -1
        if remaining == 0:
            break
        time.sleep(1)
    evidence = {"schema_version": 1, "records_to_scan": remaining, "completed": remaining == 0}
    write_json(output, evidence)
    return evidence


def zap_context(base: str, target: str) -> str:
    created = zap_api(base, "/JSON/context/action/newContext/", contextName="benchmark")
    context_id = created.get("contextId") if isinstance(created, dict) else None
    if not context_id:
        raise ZapApiError(f"ZAP context creation returned no contextId: {created!r}")
    pattern = re.escape(target.rstrip("/")) + ".*"
    zap_api(base, "/JSON/context/action/includeInContext/", contextName="benchmark", regex=pattern)
    return str(context_id)


def zap_active(base: str, target: str, output: Path, timeout: float) -> dict:
    context_id = zap_context(base, target)
    started = zap_api(
        base,
        "/JSON/ascan/action/scan/",
        url=target,
        recurse="true",
        inScopeOnly="true",
        contextId=context_id,
    )
    scan_id = started.get("scan", "") if isinstance(started, dict) else ""
    if not scan_id:
        raise ZapApiError(f"ZAP active scan returned no scan ID: {started!r}")
    status = "0"
    deadline = time.monotonic() + timeout
    while scan_id and time.monotonic() < deadline:
        response = zap_api(base, "/JSON/ascan/view/status/", scanId=scan_id)
        status = str(response.get("status", "0")) if isinstance(response, dict) else "0"
        if status == "100":
            break
        time.sleep(1)
    evidence = {
        "schema_version": 1,
        "scan_id": scan_id,
        "status": status,
        "completed": status == "100",
        "context_id": context_id,
        "scope_url": target,
        "in_scope_only": True,
    }
    write_json(output, evidence)
    return evidence


def zap_reports(base: str, target: str, output_dir: Path) -> None:
    for template, filename in (("traditional-json-plus", "zap-report.json"), ("sarif-json", "raw.sarif")):
        response = zap_api(
            base,
            "/JSON/reports/action/generate/",
            title="OWASP BenchmarkPython ZAP report",
            template=template,
            theme="original",
            contexts="benchmark",
            sites=target,
            reportDir="/zap/wrk/artifacts",
            reportFileName=filename,
            display="false",
        )
        if isinstance(response, dict) and ("error" in response or response.get("code") not in (None, 0, "0", "OK", "ok")):
            raise ZapApiError(f"ZAP report generation failed for {template}: {response}")
        report = output_dir / filename
        if not report.is_file() or report.stat().st_size == 0:
            raise ZapApiError(f"ZAP report API did not create {filename}")


def zap_metadata(
    base: str,
    output_dir: Path,
    image: str,
    digest: str,
    platform_digest: str,
    plan: Path,
    project: str,
    target: str,
) -> None:
    addons = zap_api(base, "/JSON/core/view/addons/")
    write_json(output_dir / "zap-runtime.json", {
        "schema_version": 1,
        "image": image,
        "image_digest": digest,
        "platform_digest": platform_digest,
        "compose_project": project,
        "target_url": target,
        "automation_plan": plan.name,
        "automation_plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "version": zap_api(base, "/JSON/core/view/version/"),
        "addons": addons,
        "addons_sha256": hashlib.sha256(
            json.dumps(addons, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    })


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("manifest", help="convert crawler XML to JSON")
    manifest.add_argument("--crawler", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    har = subparsers.add_parser("har", help="convert crawler XML to a deterministic HAR for ZAP")
    har.add_argument("--crawler", type=Path, required=True)
    har.add_argument("--base-url", required=True)
    har.add_argument("--allow-remote", action="store_true")
    har.add_argument("--output", type=Path, required=True)
    run = subparsers.add_parser("replay", help="send every crawler request")
    run.add_argument("--crawler", type=Path, required=True)
    run.add_argument("--base-url", required=True)
    run.add_argument("--proxy")
    run.add_argument("--timeout", type=float, default=15.0)
    run.add_argument("--insecure", action="store_true")
    run.add_argument("--allow-remote", action="store_true", help="allow a non-loopback benchmark host")
    run.add_argument("--coverage-output", type=Path, required=True)
    zh = subparsers.add_parser("zap-history")
    zh.add_argument("--base", required=True)
    zh.add_argument("--coverage", type=Path, required=True)
    zh.add_argument("--output", type=Path, required=True)
    zp = subparsers.add_parser("zap-passive")
    zp.add_argument("--base", required=True)
    zp.add_argument("--output", type=Path, required=True)
    zp.add_argument("--timeout", type=float, default=900)
    za = subparsers.add_parser("zap-active")
    za.add_argument("--base", required=True)
    za.add_argument("--target", required=True)
    za.add_argument("--output", type=Path, required=True)
    za.add_argument("--timeout", type=float, default=1800)
    zr = subparsers.add_parser("zap-reports")
    zr.add_argument("--base", required=True)
    zr.add_argument("--target", required=True)
    zr.add_argument("--output-dir", type=Path, required=True)
    zm = subparsers.add_parser("zap-metadata")
    zm.add_argument("--base", required=True)
    zm.add_argument("--output-dir", type=Path, required=True)
    zm.add_argument("--image", required=True)
    zm.add_argument("--digest", required=True)
    zm.add_argument("--platform-digest", required=True)
    zm.add_argument("--plan", type=Path, required=True)
    zm.add_argument("--project", required=True)
    zm.add_argument("--target", required=True)
    args = parser.parse_args()
    cases = parse_crawler(args.crawler)
    if args.command == "manifest":
        write_json(args.output, {"schema_version": 1, "total": len(cases), "cases": cases})
    elif args.command == "har":
        write_json(args.output, build_har(cases, args.base_url, args.allow_remote))
    elif args.command == "replay":
        write_json(
            args.coverage_output,
            replay(cases, args.base_url, args.proxy, args.timeout, args.insecure, args.allow_remote),
        )
    elif args.command == "zap-history":
        zap_history(args.base, args.coverage, args.output)
    elif args.command == "zap-passive":
        zap_passive(args.base, args.output, args.timeout)
    elif args.command == "zap-active":
        zap_active(args.base, args.target, args.output, args.timeout)
    elif args.command == "zap-reports":
        zap_reports(args.base, args.target, args.output_dir)
    elif args.command == "zap-metadata":
        zap_metadata(
            args.base,
            args.output_dir,
            args.image,
            args.digest,
            args.platform_digest,
            args.plan,
            args.project,
            args.target,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
