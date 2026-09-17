#!/usr/bin/env python3
"""Aggregate release run records without combining findings into a score."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _finding_pairs(path: Path) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    if not path.is_file():
        return pairs
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        case = value.get("case_id")
        for cwe in value.get("cwes", []):
            if case and cwe:
                pairs.add((str(case), str(cwe)))
    return pairs


def _set_hash(pairs: set[tuple[str, str]]) -> str:
    payload = "".join(f"{case}\t{cwe}\n" for case, cwe in sorted(pairs)).encode()
    return hashlib.sha256(payload).hexdigest()


def aggregate(release: Path) -> dict[str, Any]:
    manifests = sorted(release.glob("*/run-*/manifest.json"))
    runs: list[dict[str, Any]] = []
    by_tool: dict[str, list[dict[str, Any]]] = {}
    for manifest_path in manifests:
        manifest = _load(manifest_path)
        score_path = manifest_path.parent / "score.json"
        score = _load(score_path) if score_path.is_file() else None
        pairs = _finding_pairs(manifest_path.parent / "normalized.jsonl")
        run = {
            "run_id": manifest.get("run_id"),
            "tool": manifest.get("tool"),
            "method": manifest.get("method"),
            "status": manifest.get("status"),
            "manifest": str(manifest_path.relative_to(release)),
            "score": score,
            "finding_count": len(pairs),
            "finding_set_sha256": _set_hash(pairs),
        }
        runs.append(run)
        by_tool.setdefault(str(run["tool"]), []).append(run)
    stability: dict[str, Any] = {}
    for tool, tool_runs in sorted(by_tool.items()):
        scores = [run["score"] for run in tool_runs if run["score"] and run["status"] == "PASS"]
        recalls = [item["all_cases"].get("recall") for item in scores if item.get("all_cases", {}).get("recall") is not None]
        fingerprints = [run["finding_set_sha256"] for run in tool_runs if run["status"] == "PASS"]
        stability[tool] = {
            "runs": len(tool_runs),
            "pass_runs": len(scores),
            "statuses": {status: sum(1 for run in tool_runs if run["status"] == status) for status in sorted({run["status"] for run in tool_runs})},
            "recall_min": min(recalls) if recalls else None,
            "recall_max": max(recalls) if recalls else None,
            "finding_set_recurrence": len(fingerprints) - len(set(fingerprints)),
            "pairwise_identical_finding_sets": sum(
                1 for index, left in enumerate(fingerprints) for right in fingerprints[index + 1 :] if left == right
            ),
        }
    return {
        "schema_version": 1,
        "release": release.name,
        "matching_policy": "each run retains and scores its own normalized findings; runs are never unioned",
        "unioned_findings": False,
        "runs": runs,
        "stability": stability,
    }


def write_outputs(result: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md = [f"# Release {result['release']}", "", "Findings are scored per run; no run findings are unioned.", "", "| Run | Tool | Method | Status | Finding set SHA-256 |", "| --- | --- | --- | --- | --- |"]
    for run in result["runs"]:
        md.append(f"| {run['run_id']} | {run['tool']} | {run['method']} | {run['status']} | `{run['finding_set_sha256']}` |")
    md.extend(["", "## Stability", "", "| Tool | Runs | PASS | Recall range | Repeated finding sets |", "| --- | ---: | ---: | --- | ---: |"])
    for tool, value in result["stability"].items():
        low, high = value["recall_min"], value["recall_max"]
        md.append(f"| {tool} | {value['runs']} | {value['pass_runs']} | {low}–{high} | {value['finding_set_recurrence']} |")
    output.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")
    with output.with_suffix(".csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["run_id", "tool", "method", "status", "finding_count", "finding_set_sha256"])
        for run in result["runs"]:
            writer.writerow([run[key] for key in ("run_id", "tool", "method", "status", "finding_count", "finding_set_sha256")])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_outputs(aggregate(args.release.resolve()), args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
