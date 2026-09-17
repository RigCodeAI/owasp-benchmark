#!/usr/bin/env python3
"""Sanitize Snyk scanner streams before they become retained artifacts."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

from snyk_provenance import _private_query_urls, _private_text_assignments


REDACTED_ASSIGNMENT = "[SNYK_OUTPUT_REDACTED: sensitive-line]"
REDACTED_URL = "[SNYK_OUTPUT_REDACTED: sensitive-url]"


def _line_ending(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith(("\r", "\n")):
        return line[-1]
    return ""


def sanitize_text(text: str, replacements: Iterable[tuple[str, str]]) -> tuple[str, dict[str, int]]:
    """Return sanitized text and deterministic counts without retaining values."""
    replacement_values = [(value, marker) for value, marker in replacements if value]
    replacement_values.sort(key=lambda item: len(item[0]), reverse=True)
    output: list[str] = []
    counts = {
        "local_replacements": 0,
        "sensitive_assignment_lines": 0,
        "sensitive_url_lines": 0,
    }
    for line in text.splitlines(keepends=True):
        ending = _line_ending(line)
        if _private_text_assignments(line):
            output.append(REDACTED_ASSIGNMENT + ending)
            counts["sensitive_assignment_lines"] += 1
            continue
        if _private_query_urls(line):
            output.append(REDACTED_URL + ending)
            counts["sensitive_url_lines"] += 1
            continue
        sanitized = line
        for value, marker in replacement_values:
            occurrences = sanitized.count(value)
            if occurrences:
                counts["local_replacements"] += occurrences
                sanitized = sanitized.replace(value, marker)
        output.append(sanitized)
    if text and not output:
        output.append(text)
    return "".join(output), counts


def sanitize_stream(input_path: Path, output_path: Path, replacements: Iterable[tuple[str, str]]) -> dict[str, int]:
    text = input_path.read_bytes().decode("utf-8", errors="replace")
    sanitized, counts = sanitize_text(text, replacements)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(sanitized, encoding="utf-8")
    os.chmod(output_path, 0o600)
    counts["input_bytes"] = len(text.encode("utf-8"))
    counts["output_bytes"] = len(sanitized.encode("utf-8"))
    return counts


def sanitize_files(
    streams: dict[str, tuple[Path, Path]],
    metadata_path: Path,
    replacements: Iterable[tuple[str, str]],
) -> dict[str, object]:
    replacement_values = tuple(replacements)
    stream_metadata = {
        name: sanitize_stream(input_path, output_path, replacement_values)
        for name, (input_path, output_path) in sorted(streams.items())
    }
    totals = {
        key: sum(int(values.get(key, 0)) for values in stream_metadata.values())
        for key in (
            "input_bytes", "output_bytes", "local_replacements",
            "sensitive_assignment_lines", "sensitive_url_lines",
        )
    }
    value = {"schema_version": 1, "streams": stream_metadata, "totals": totals}
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(metadata_path, 0o600)
    return value


def _replacements(args: argparse.Namespace) -> list[tuple[str, str]]:
    return [
        (args.source_tree, "<SOURCE_SCOPE_TREE>"),
        (args.source_scope, "<SOURCE_SCOPE>"),
        (args.artifact_dir, "<ARTIFACT_DIR>"),
        (args.repo_root, "<HARNESS_ROOT>"),
        (args.benchmark_root, "<BENCHMARK_ROOT>"),
        (args.cache_dir, "<SNYK_CACHE>"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdout-input", type=Path, required=True)
    parser.add_argument("--stderr-input", type=Path, required=True)
    parser.add_argument("--stdout-output", type=Path, required=True)
    parser.add_argument("--stderr-output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-scope", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--benchmark-root", required=True)
    parser.add_argument("--cache-dir", required=True)
    args = parser.parse_args()
    try:
        sanitize_files(
            {
                "stdout": (args.stdout_input, args.stdout_output),
                "stderr": (args.stderr_input, args.stderr_output),
            },
            args.metadata,
            _replacements(args),
        )
    except (OSError, UnicodeError, ValueError):
        print("Snyk output sanitization failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
