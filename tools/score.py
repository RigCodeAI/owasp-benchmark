#!/usr/bin/env python3
"""Score normalized scanner findings against BenchmarkPython ground truth."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from common import case_id, load_aliases, normalize_cwe


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALIASES = ROOT / "configs" / "cwe-aliases.json"


def load_expected(path: Path, aliases: dict[int, int]) -> dict[str, dict]:
    expected: dict[str, dict] = {}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = csv.reader(line for line in handle if not line.lstrip().startswith("#"))
        for row_number, row in enumerate(rows, 1):
            if not row or not any(cell.strip() for cell in row):
                continue
            if len(row) < 4:
                raise ValueError(f"expected-results row {row_number} has fewer than 4 columns")
            identifier = case_id(row[0])
            cwe = normalize_cwe(row[3], aliases)
            if identifier is None or cwe is None:
                raise ValueError(f"invalid expected-results row {row_number}: {row!r}")
            truth = row[2].strip().lower()
            if truth not in {"true", "false"}:
                raise ValueError(f"invalid vulnerability flag at row {row_number}: {row[2]!r}")
            if identifier in expected:
                raise ValueError(f"duplicate expected case: {identifier}")
            expected[identifier] = {
                "category": row[1].strip(),
                "vulnerable": truth == "true",
                "cwe": cwe,
            }
    if not expected:
        raise ValueError("expected-results file contained no cases")
    return expected


def load_findings(path: Path, aliases: dict[int, int]) -> tuple[set[tuple[str, int]], dict]:
    detections: set[tuple[str, int]] = set()
    diagnostics = {
        "raw_findings": 0,
        "findings_without_case_id": 0,
        "findings_without_cwe": 0,
        "duplicate_detection_pairs": 0,
    }
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            diagnostics["raw_findings"] += 1
            try:
                finding = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
            identifier = case_id(finding.get("case_id", ""))
            if identifier is None:
                diagnostics["findings_without_case_id"] += 1
                continue
            raw_cwes = finding.get("cwes", [])
            if not isinstance(raw_cwes, list):
                raw_cwes = [raw_cwes]
            cwes = {normalize_cwe(value, aliases) for value in raw_cwes}
            cwes.discard(None)
            if not cwes:
                diagnostics["findings_without_cwe"] += 1
                continue
            for cwe in cwes:
                pair = (identifier, int(cwe))
                if pair in detections:
                    diagnostics["duplicate_detection_pairs"] += 1
                detections.add(pair)
    diagnostics["unique_detection_pairs"] = len(detections)
    return detections, diagnostics


def load_coverage(path: Path | None) -> set[str] | None:
    if path is None:
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = raw.get("cases", raw) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("coverage must be a list or an object with a cases list")
    covered: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            identifier = case_id(entry)
            exercised = True
        elif isinstance(entry, dict):
            identifier = case_id(entry.get("case_id", entry.get("id", "")))
            exercised = bool(entry.get("exercised", entry.get("success", False)))
        else:
            continue
        if identifier and exercised:
            covered.add(identifier)
    return covered


def ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def calculate(expected: dict[str, dict], detected: set[tuple[str, int]], included: Iterable[str]) -> dict:
    included_ids = set(included)
    totals = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    per_cwe: dict[int, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for identifier in sorted(included_ids):
        truth = expected[identifier]
        found = (identifier, truth["cwe"]) in detected
        bucket = "tp" if truth["vulnerable"] and found else "fn" if truth["vulnerable"] else "fp" if found else "tn"
        totals[bucket] += 1
        per_cwe[truth["cwe"]][bucket] += 1

    positives = totals["tp"] + totals["fn"]
    negatives = totals["fp"] + totals["tn"]
    precision_denominator = totals["tp"] + totals["fp"]
    recall = ratio(totals["tp"], positives)
    fpr = ratio(totals["fp"], negatives)
    precision = ratio(totals["tp"], precision_denominator)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = round(2 * precision * recall / (precision + recall), 6)

    categories = {}
    recalls: list[float] = []
    fprs: list[float] = []
    for cwe, counts in sorted(per_cwe.items()):
        cwe_recall = ratio(counts["tp"], counts["tp"] + counts["fn"])
        cwe_fpr = ratio(counts["fp"], counts["fp"] + counts["tn"])
        if cwe_recall is not None:
            recalls.append(cwe_recall)
        if cwe_fpr is not None:
            fprs.append(cwe_fpr)
        categories[f"CWE-{cwe}"] = {
            **counts,
            "recall": cwe_recall,
            "false_positive_rate": cwe_fpr,
        }
    macro_recall = round(sum(recalls) / len(recalls), 6) if recalls else None
    macro_fpr = round(sum(fprs) / len(fprs), 6) if fprs else None
    return {
        "cases": len(included_ids),
        "vulnerable": positives,
        "safe": negatives,
        **totals,
        "recall": recall,
        "miss_rate": None if recall is None else round(1 - recall, 6),
        "false_positive_rate": fpr,
        "precision": precision,
        "f1": f1,
        "accuracy": ratio(totals["tp"] + totals["tn"], len(included_ids)),
        "macro_recall": macro_recall,
        "macro_false_positive_rate": macro_fpr,
        "owasp_score": None if macro_recall is None or macro_fpr is None else round(macro_recall - macro_fpr, 6),
        "by_cwe": categories,
    }


def score(expected_path: Path, findings_path: Path, aliases_path: Path, coverage_path: Path | None) -> dict:
    aliases = load_aliases(aliases_path)
    expected = load_expected(expected_path, aliases)
    detections, diagnostics = load_findings(findings_path, aliases)
    expected_pairs = {(identifier, truth["cwe"]) for identifier, truth in expected.items()}
    diagnostics["matched_detection_pairs"] = len(detections & expected_pairs)
    diagnostics["unmatched_detection_pairs"] = len(detections - expected_pairs)
    diagnostics["unknown_case_pairs"] = sum(1 for identifier, _ in detections if identifier not in expected)
    alerted_case_ids = {identifier for identifier, _ in detections}
    diagnostics["safe_cases_with_any_alert"] = sum(
        1 for identifier, truth in expected.items() if not truth["vulnerable"] and identifier in alerted_case_ids
    )
    diagnostics["vulnerable_cases_with_wrong_cwe_only"] = sum(
        1
        for identifier, truth in expected.items()
        if truth["vulnerable"]
        and identifier in alerted_case_ids
        and (identifier, truth["cwe"]) not in detections
    )

    result = {
        "schema_version": 1,
        "matching_policy": "exact case ID and normalized expected CWE; duplicate pairs count once",
        "all_cases": calculate(expected, detections, expected),
        "diagnostics": diagnostics,
    }
    covered = load_coverage(coverage_path)
    if covered is not None:
        known_covered = covered & set(expected)
        result["coverage"] = {
            "exercised": len(known_covered),
            "not_run": len(expected) - len(known_covered),
            "unknown_case_ids": len(covered - set(expected)),
            "rate": ratio(len(known_covered), len(expected)),
        }
        result["covered_cases"] = calculate(expected, detections, known_covered)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = score(args.expected, args.findings, args.aliases, args.coverage)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
