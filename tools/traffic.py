#!/usr/bin/env python3
"""Build or replay deterministic HTTP traffic from BenchmarkPython's crawler XML."""

from __future__ import annotations

import argparse
import ipaddress
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from common import case_id


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
            "method": "GET" if element.findall("getparam") else "POST",
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
        started = time.monotonic()
        status = None
        error = None
        exercised = False
        reached_target = False
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                response.read(1024)
                reached_target = True
                exercised = 200 <= status < 400
        except urllib.error.HTTPError as exc:
            status = exc.code
            reached_target = True
            error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = str(exc)
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
    args = parser.parse_args()
    cases = parse_crawler(args.crawler)
    if args.command == "manifest":
        write_json(args.output, {"schema_version": 1, "total": len(cases), "cases": cases})
    elif args.command == "har":
        write_json(args.output, build_har(cases, args.base_url, args.allow_remote))
    else:
        write_json(
            args.coverage_output,
            replay(cases, args.base_url, args.proxy, args.timeout, args.insecure, args.allow_remote),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
