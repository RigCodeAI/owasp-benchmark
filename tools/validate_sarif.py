#!/usr/bin/env python3
"""Fail-closed structural validation for SARIF 2.1.0 scanner output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class SarifError(ValueError):
    pass


def _object(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        raise SarifError(f"{path} must be an object")
    return value


def _string(value: Any, path: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise SarifError(f"{path} must be a{' non-empty' if nonempty else ''} string")
    return value


def validate(document: Any) -> None:
    root = _object(document, "$" )
    if root.get("version") != "2.1.0":
        raise SarifError("$.version must be exactly 2.1.0")
    runs = root.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SarifError("$.runs must be a non-empty array")
    for run_index, raw_run in enumerate(runs):
        path = f"$.runs[{run_index}]"
        run = _object(raw_run, path)
        tool = _object(run.get("tool"), f"{path}.tool")
        driver = _object(tool.get("driver"), f"{path}.tool.driver")
        _string(driver.get("name"), f"{path}.tool.driver.name", nonempty=True)
        if "rules" in driver:
            rules = driver["rules"]
            if not isinstance(rules, list):
                raise SarifError(f"{path}.tool.driver.rules must be an array")
            for rule_index, raw_rule in enumerate(rules):
                rule = _object(raw_rule, f"{path}.tool.driver.rules[{rule_index}]")
                _string(rule.get("id"), f"{path}.tool.driver.rules[{rule_index}].id", nonempty=True)
        results = run.get("results")
        if not isinstance(results, list):
            raise SarifError(f"{path}.results must be an array")
        for result_index, raw_result in enumerate(results):
            result_path = f"{path}.results[{result_index}]"
            result = _object(raw_result, result_path)
            if "ruleId" in result:
                _string(result["ruleId"], f"{result_path}.ruleId")
            message = _object(result.get("message"), f"{result_path}.message")
            if not isinstance(message.get("text"), str) and not isinstance(message.get("markdown"), str):
                raise SarifError(f"{result_path}.message requires text or markdown")
            if "locations" in result:
                locations = result["locations"]
                if not isinstance(locations, list):
                    raise SarifError(f"{result_path}.locations must be an array")
                for location_index, raw_location in enumerate(locations):
                    location_path = f"{result_path}.locations[{location_index}]"
                    location = _object(raw_location, location_path)
                    if "physicalLocation" not in location and "logicalLocations" not in location:
                        raise SarifError(f"{location_path} needs physicalLocation or logicalLocations")
                    if "physicalLocation" in location:
                        physical = _object(location["physicalLocation"], f"{location_path}.physicalLocation")
                        if "artifactLocation" in physical:
                            artifact = _object(physical["artifactLocation"], f"{location_path}.physicalLocation.artifactLocation")
                            if "uri" in artifact:
                                _string(artifact["uri"], f"{location_path}.physicalLocation.artifactLocation.uri")
                        if "region" in physical:
                            region = _object(physical["region"], f"{location_path}.physicalLocation.region")
                            if "startLine" in region and (not isinstance(region["startLine"], int) or region["startLine"] < 1):
                                raise SarifError(f"{location_path}.physicalLocation.region.startLine must be >= 1")
                    if "logicalLocations" in location:
                        logical = location["logicalLocations"]
                        if not isinstance(logical, list):
                            raise SarifError(f"{location_path}.logicalLocations must be an array")
                        for logical_index, item in enumerate(logical):
                            _object(item, f"{location_path}.logicalLocations[{logical_index}]")
            if "properties" in result:
                _object(result["properties"], f"{result_path}.properties")


def validate_file(path: Path) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SarifError(f"invalid SARIF JSON: {exc}") from exc
    validate(document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate_file(args.input)
    except SarifError as exc:
        print(f"ERROR: {exc}")
        return 1
    print("SARIF 2.1.0 structure verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
