#!/usr/bin/env python3
"""Freeze a local Semgrep rule file and prove its immutable checksum."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path


MUTABLE_RULES = {"p/python", "python", "p/default", "auto", "p/ci"}
DEFAULT_SOURCE_URL = "https://semgrep.dev/c/p/python"
DEFAULT_LICENSE_ID = "Semgrep Rules License v1.0"
DEFAULT_LICENSE_URL = "https://semgrep.dev/legal/rules-license/"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_mutable_reference(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized in MUTABLE_RULES or normalized.startswith("p/")


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _rule_count(path: Path) -> int:
    return len(re.findall(r"(?m)^\s*-\s+id\s*:", path.read_text(encoding="utf-8")))


def freeze(
    source: str,
    output: Path,
    *,
    resolved_from: str | None = None,
    source_url: str = DEFAULT_SOURCE_URL,
    license_id: str = DEFAULT_LICENSE_ID,
    license_url: str = DEFAULT_LICENSE_URL,
    cli_mode: str = "community",
    account_status: str = "unauthenticated",
    auth_status: str = "not_applicable",
) -> dict:
    source_path = Path(source).expanduser()
    if is_mutable_reference(source) and resolved_from is None:
        raise ValueError(f"mutable Semgrep registry rules are not publishable: {source}")
    if not source_path.is_file():
        raise ValueError(f"resolved Semgrep rules file does not exist: {source_path}")
    output = output.resolve()
    if output.exists():
        raise ValueError(f"refusing to replace frozen rules: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(source_path.read_bytes())
    digest = sha256(output)
    output.chmod(0o444)
    record = {
        "schema_version": 1,
        "source": resolved_from or source,
        "source_kind": "resolved-local-file",
        "path": output.name,
        "sha256": digest,
        "bytes": output.stat().st_size,
        "frozen": True,
        "mutable_registry": False,
        "publishable": False,
        "redistribution": "prohibited",
        "redistribution_allowed": False,
        "source_url": source_url,
        "source_ref": resolved_from or source,
        "retrieved_at": _utc_now(),
        "license": {"id": license_id, "url": license_url},
        "cli_mode": cli_mode,
        "account_status": account_status,
        "auth_status": auth_status,
        "rule_count": _rule_count(output),
    }
    record_path = output.with_name(output.name + ".manifest.json")
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    record["manifest"] = record_path.name
    # Add the manifest pointer before writing the final record; its hash is not
    # part of the rule-file identity and therefore cannot cause a cycle.
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def _read_record(manifest: Path) -> tuple[dict | None, list[str]]:
    try:
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"invalid Semgrep rules manifest: {exc}"]
    if not isinstance(record, dict):
        return None, ["Semgrep rules manifest must be an object"]
    return record, []


def verify(
    rules: Path,
    manifest: Path,
    *,
    expected_sha256: str | None = None,
    expected_rule_count: int | None = None,
) -> list[str]:
    errors: list[str] = []
    record, read_errors = _read_record(manifest)
    if record is None:
        return read_errors
    if record.get("frozen") is not True or record.get("mutable_registry") is not False:
        errors.append("rules manifest does not assert immutable resolved rules")
    if record.get("publishable") is not False:
        errors.append("Semgrep rules snapshot must remain nonpublishable")
    if record.get("redistribution") != "prohibited" or record.get("redistribution_allowed") is not False:
        errors.append("Semgrep rules redistribution must be prohibited")
    if record.get("path") != rules.name:
        errors.append("rules manifest path does not match the frozen rules file")
    if not isinstance(record.get("sha256"), str) or len(record["sha256"]) != 64:
        errors.append("rules manifest has no valid SHA-256")
    if expected_sha256 is not None and record.get("sha256") != expected_sha256:
        errors.append("frozen Semgrep rules SHA-256 does not match the release snapshot")
    if record.get("source_url") != DEFAULT_SOURCE_URL:
        errors.append("rules manifest source URL does not match the release snapshot")
    if record.get("source_ref") != "p/python":
        errors.append("rules manifest source ref does not match the release snapshot")
    if not isinstance(record.get("retrieved_at"), str) or not record["retrieved_at"].endswith("Z"):
        errors.append("rules manifest lacks a UTC retrieval timestamp")
    license_value = record.get("license")
    if not isinstance(license_value, dict) or license_value.get("id") != DEFAULT_LICENSE_ID or license_value.get("url") != DEFAULT_LICENSE_URL:
        errors.append("rules manifest lacks the Semgrep Rules License v1.0 metadata")
    for key, expected in {
        "cli_mode": "community",
        "account_status": "unauthenticated",
        "auth_status": "not_applicable",
    }.items():
        if record.get(key) != expected:
            errors.append(f"rules manifest {key} does not match the release snapshot")
    if not isinstance(record.get("rule_count"), int) or record["rule_count"] < 0:
        errors.append("rules manifest lacks a rule count")
    if expected_rule_count is not None and record.get("rule_count") != expected_rule_count:
        errors.append("frozen Semgrep rule count does not match the release snapshot")
    if not rules.is_file():
        errors.append(f"frozen rules file missing: {rules}")
    elif sha256(rules) != record.get("sha256"):
        errors.append("frozen Semgrep rules SHA-256 mismatch")
    try:
        mode = rules.stat().st_mode & 0o222
        if mode:
            errors.append("frozen Semgrep rules file is writable")
    except OSError as exc:
        errors.append(str(exc))
    return errors


def provenance(manifest: Path, output: Path, *, expected_sha256: str, expected_rule_count: int) -> dict:
    """Write only sanitized, publishable provenance; never copy rule contents."""
    record, errors = _read_record(manifest)
    if errors or record is None:
        raise ValueError("; ".join(errors) or "invalid Semgrep rules manifest")
    value = {
        "schema_version": 1,
        "publishable": False,
        "redistribution": "prohibited",
        "redistribution_allowed": False,
        "sha256": record.get("sha256"),
        "bytes": record.get("bytes"),
        "rule_count": record.get("rule_count"),
        "source_url": record.get("source_url"),
        "source_ref": record.get("source_ref"),
        "retrieved_at": record.get("retrieved_at"),
        "license": record.get("license"),
        "cli_mode": record.get("cli_mode"),
        "account_status": record.get("account_status"),
        "auth_status": record.get("auth_status"),
        "expected_sha256": expected_sha256,
        "expected_rule_count": expected_rule_count,
    }
    if value["sha256"] != expected_sha256 or value["rule_count"] != expected_rule_count:
        raise ValueError("frozen Semgrep provenance does not match the release snapshot")
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("freeze")
    create.add_argument("--source", required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--resolved-from")
    check = sub.add_parser("verify")
    check.add_argument("--rules", type=Path, required=True)
    check.add_argument("--manifest", type=Path, required=True)
    check.add_argument("--expected-sha256")
    check.add_argument("--expected-rule-count", type=int)
    check.add_argument("--provenance-output", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "freeze":
            print(json.dumps(freeze(args.source, args.output, resolved_from=args.resolved_from), sort_keys=True))
            return 0
        errors = verify(
            args.rules,
            args.manifest,
            expected_sha256=args.expected_sha256,
            expected_rule_count=args.expected_rule_count,
        )
        if not errors and args.provenance_output:
            provenance(
                args.manifest,
                args.provenance_output,
                expected_sha256=args.expected_sha256 or "",
                expected_rule_count=args.expected_rule_count if args.expected_rule_count is not None else -1,
            )
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Semgrep rules verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
