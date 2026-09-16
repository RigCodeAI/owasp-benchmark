"""Shared helpers for the benchmark harness."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


CASE_RE = re.compile(r"BenchmarkTest(\d{1,5})", re.IGNORECASE)
CWE_RE = re.compile(r"(?:CWE[-_: ]?)?(\d{1,5})", re.IGNORECASE)


def case_id(value: object) -> str | None:
    match = CASE_RE.search(str(value))
    if not match:
        return None
    return f"BenchmarkTest{int(match.group(1)):05d}"


def cwe_number(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    match = CWE_RE.fullmatch(str(value).strip())
    if not match:
        return None
    return int(match.group(1))


def load_aliases(path: Path | None) -> dict[int, int]:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {int(key): int(value) for key, value in raw.items()}


def normalize_cwe(value: object, aliases: dict[int, int]) -> int | None:
    number = cwe_number(value)
    if number is None:
        return None
    return aliases.get(number, number)


def strings(value: Any):
    """Yield strings and scalar values from an arbitrary JSON value."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif value is not None:
        yield str(value)
