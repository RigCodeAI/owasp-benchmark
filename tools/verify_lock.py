#!/usr/bin/env python3
"""Verify the pinned BenchmarkPython artifacts and expected case counts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from score import load_expected
from common import load_aliases


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(benchmark: Path, lock_path: Path) -> list[str]:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for name, artifact in lock["artifacts"].items():
        path = benchmark / artifact["path"]
        if not path.is_file():
            errors.append(f"{name}: missing {path}")
        elif sha256(path) != artifact["sha256"]:
            errors.append(f"{name}: SHA-256 mismatch")
    expected_path = benchmark / lock["artifacts"]["expected_results"]["path"]
    if expected_path.is_file():
        expected = load_expected(expected_path, load_aliases(ROOT / "configs" / "cwe-aliases.json"))
        vulnerable = sum(1 for item in expected.values() if item["vulnerable"])
        actual = {
            "cases": len(expected),
            "vulnerable": vulnerable,
            "safe": len(expected) - vulnerable,
            "cwes": len({item["cwe"] for item in expected.values()}),
        }
        if actual != lock["counts"]:
            errors.append(f"expected-results counts differ: {actual!r}")
        expected_ids = set(expected)
        crawler_path = benchmark / lock["artifacts"]["crawler"]["path"]
        if crawler_path.is_file():
            crawler_ids = {
                node.get("tcName") for node in ET.parse(crawler_path).getroot().findall("benchmarkTest")
            }
            if crawler_ids != expected_ids:
                errors.append(
                    f"crawler case IDs differ: expected {len(expected_ids)}, found {len(crawler_ids)} unique IDs"
                )
        openapi_path = benchmark / lock["artifacts"]["openapi"]["path"]
        if openapi_path.is_file():
            openapi_ids = set(re.findall(r"BenchmarkTest\d{5}", openapi_path.read_text(encoding="utf-8")))
            if openapi_ids != expected_ids:
                errors.append(
                    f"OpenAPI case IDs differ: expected {len(expected_ids)}, found {len(openapi_ids)} unique IDs"
                )
    git_dir = benchmark / ".git"
    if git_dir.exists():
        commit = subprocess.run(
            ["git", "-C", str(benchmark), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
        ).stdout.strip()
        if commit and commit != lock["commit"]:
            errors.append(f"git commit mismatch: {commit}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, default=ROOT / "benchmark")
    parser.add_argument("--lock", type=Path, default=ROOT / "benchmark.lock.json")
    args = parser.parse_args()
    errors = verify(args.benchmark, args.lock)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Benchmark lock verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
