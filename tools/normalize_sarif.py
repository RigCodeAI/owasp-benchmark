#!/usr/bin/env python3
"""Convert SARIF from supported scanners into the common JSONL format."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from common import CASE_RE, case_id, load_aliases, normalize_cwe, strings


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALIASES = ROOT / "configs" / "cwe-aliases.json"
CWE_SEARCH_RE = re.compile(r"\bCWE[-_: ]?(\d{1,5})\b", re.IGNORECASE)


def message_text(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("text") or value.get("markdown") or "")
    return str(value or "")


def rules_for(run: dict) -> dict[str, dict]:
    rules: dict[str, dict] = {}
    containers = [run.get("tool", {}).get("driver", {})]
    containers.extend(run.get("tool", {}).get("extensions", []))
    for container in containers:
        for rule in container.get("rules", []) or []:
            if rule.get("id"):
                rules[str(rule["id"])] = rule
    return rules


def location_data(result: dict) -> tuple[str | None, int | None]:
    for location in result.get("locations", []) or []:
        physical = location.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        uri = artifact.get("uri")
        region = physical.get("region", {})
        if uri:
            return str(uri), region.get("startLine")
        logical = location.get("logicalLocations", []) or []
        if logical:
            return str(logical[0].get("fullyQualifiedName") or logical[0].get("name") or ""), None
    return None, None


def collect_cwes(result: dict, rule: dict, aliases: dict[int, int]) -> list[int]:
    found: set[int] = set()
    values = [result.get("properties", {}), rule.get("properties", {}), rule.get("relationships", [])]
    values.extend([result.get("taxa", []), rule.get("help", {}), rule.get("shortDescription", {})])
    for value in values:
        for text in strings(value):
            for match in CWE_SEARCH_RE.finditer(text):
                cwe = normalize_cwe(match.group(1), aliases)
                if cwe is not None:
                    found.add(cwe)
    return sorted(found)


def collect_case(result: dict) -> str | None:
    preferred = [
        result.get("locations", []),
        result.get("codeFlows", []),
        result.get("stacks", []),
        result.get("message", {}),
        result.get("properties", {}),
    ]
    for value in preferred:
        for text in strings(value):
            if CASE_RE.search(text):
                return case_id(text)
    return None


def normalize(document: dict, aliases: dict[int, int], source_name: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    diagnostics = {"sarif_results": 0, "without_case_id": 0, "without_cwe": 0}
    for run_index, run in enumerate(document.get("runs", []) or []):
        rules = rules_for(run)
        driver = run.get("tool", {}).get("driver", {})
        tool_name = str(driver.get("name") or "unknown")
        for result_index, result in enumerate(run.get("results", []) or []):
            diagnostics["sarif_results"] += 1
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id, {})
            identifier = collect_case(result)
            cwes = collect_cwes(result, rule, aliases)
            if identifier is None:
                diagnostics["without_case_id"] += 1
            if not cwes:
                diagnostics["without_cwe"] += 1
            file_name, line = location_data(result)
            findings.append(
                {
                    "schema_version": 1,
                    "case_id": identifier,
                    "cwes": [f"CWE-{cwe}" for cwe in cwes],
                    "tool": tool_name,
                    "rule_id": rule_id or None,
                    "rule_name": rule.get("name") or message_text(rule.get("shortDescription")) or None,
                    "level": result.get("level"),
                    "file_or_url": file_name,
                    "line": line,
                    "message": message_text(result.get("message")),
                    "raw_ref": f"{source_name}#run={run_index}&result={result_index}",
                }
            )
    diagnostics["normalized_findings"] = len(findings)
    return findings, diagnostics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostics", type=Path)
    parser.add_argument("--aliases", type=Path, default=DEFAULT_ALIASES)
    args = parser.parse_args()
    document = json.loads(args.input.read_text(encoding="utf-8"))
    findings, diagnostics = normalize(document, load_aliases(args.aliases), args.input.name)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in findings), encoding="utf-8")
    if args.diagnostics:
        args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
        args.diagnostics.write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(diagnostics, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
