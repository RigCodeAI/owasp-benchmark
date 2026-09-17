#!/usr/bin/env python3
"""Create and validate sanitized Snyk Code provenance evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from schema import SchemaError, validate_file
from source_scope import verify as verify_source_scope


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "snyk-provenance.schema.json"
VENDOR = ROOT / "configs" / "vendors" / "snyk.json"
COMMAND = "snyk code test <source-scope/tree> --sarif-file-output=raw.sarif"
PRIVATE_KEY_PARTS = (
    "token", "secret", "password", "username", "organization", "org", "account", "path", "cache",
)
PRIVATE_TEXT_RE = re.compile(
    r"(?ix)"
    r"(?:\bfile:///[^\s\"']+)"
    r"|(?:^|[\s\"'=])/(?:private|Users|home|tmp|var)/"
    r"|(?:^|[\s\"'=(:])/(?!/)[A-Za-z0-9._~-][^\s\"']*"
    r"|(?:^|[\s\"'=])[A-Za-z]:[\\/]"
)
TEXT_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_. -]{0,127}?)\s*[:=]\s*[^\s,;]+"
)
TEXT_URL_RE = re.compile(r"(?i)https?://[^\s\"'<>]+")
SENSITIVE_QUERY_PARTS = (
    "token", "apikey", "authkey", "accesskey", "secret", "password",
    "organization", "org", "account", "username",
)
SAFE_RELATIVE_PATH_KEYS = {
    "path", "paths", "source_path", "manifest_path", "scope_path", "artifact_path",
    "file_path", "source_root", "source-root", "evidence_path",
}
ALLOWED_TOP_LEVEL = {
    "schema_version", "tool", "cli_version", "binary_sha256", "authenticated",
    "consent_confirmed", "captured_at", "cache_isolated", "scan", "account_tier",
    "account_tier_status", "engine_version", "engine_version_status",
}
ALLOWED_SCAN_FIELDS = {"command", "source_scope", "output", "configuration", "exit_code_policy"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _vendor() -> dict[str, Any]:
    return json.loads(VENDOR.read_text(encoding="utf-8"))


def _safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\", "file://")):
        return False
    if re.match(r"^[A-Za-z]:[\\/]", value) or "://" in value:
        return False
    return ".." not in Path(value).parts


def _safe_relative_container(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return _safe_relative_path(value)
    if isinstance(value, list):
        return all(_safe_relative_path(item) for item in value)
    return False


def _sensitive_query_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    return any(part in normalized for part in SENSITIVE_QUERY_PARTS)


def _private_query_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme.casefold() not in {"http", "https"}:
        return False
    return any(_sensitive_query_key(key) for key, _ in parse_qsl(parsed.query, keep_blank_values=True))


def _private_query_urls(text: str) -> bool:
    return any(_private_query_url(match.group(0)) for match in TEXT_URL_RE.finditer(text))


def _private_text_assignments(text: str) -> bool:
    return any(_sensitive_query_key(match.group(1)) for match in TEXT_ASSIGNMENT_RE.finditer(text))


def _private_values(value: Any, location: str = "$", *, allow_safe_relative_paths: bool = False) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            allowlisted_metadata = {"account_tier", "account_tier_status", "cache_isolated"}
            safe_path_field = (
                allow_safe_relative_paths
                and lowered in SAFE_RELATIVE_PATH_KEYS
                and _safe_relative_container(item)
            )
            if (
                lowered not in allowlisted_metadata
                and not safe_path_field
                and any(part in lowered for part in PRIVATE_KEY_PARTS)
            ):
                errors.append(f"{location}.{key} is not an allowlisted provenance field")
            errors.extend(_private_values(item, f"{location}.{key}", allow_safe_relative_paths=allow_safe_relative_paths))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_private_values(item, f"{location}[{index}]", allow_safe_relative_paths=allow_safe_relative_paths))
    elif isinstance(value, str):
        file_uri_path = value[7:] if value.startswith("file://") else None
        if (
            value.startswith(("/", "\\\\"))
            or re.match(r"^[A-Za-z]:[\\/]", value)
            or any(token in value for token in ("/Users/", "/private/", "/home/"))
            or (file_uri_path is not None and (file_uri_path.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", file_uri_path)))
        ):
            errors.append(f"{location} contains a private path")
        if _private_query_url(value):
            errors.append(f"{location} contains a sensitive URL query parameter")
    return errors


def create(
    output: Path,
    *,
    cli_version: str | None,
    binary_sha256: str | None,
    authenticated: bool,
    consent_confirmed: bool,
    cache_isolated: bool,
) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "tool": "snyk-code",
        "cli_version": cli_version or None,
        "binary_sha256": binary_sha256 or None,
        "authenticated": authenticated,
        "consent_confirmed": consent_confirmed,
        "captured_at": utc_now(),
        "cache_isolated": cache_isolated,
        "scan": {
            "command": COMMAND,
            "source_scope": "tree",
            "output": "raw.sarif",
            "configuration": "default",
            "exit_code_policy": "1_findings",
        },
        "account_tier": None,
        "account_tier_status": "not_exposed",
        "engine_version": None,
        "engine_version_status": "not_exposed",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def enrich_engine_version(provenance_path: Path, sarif_path: Path) -> dict[str, Any]:
    value = json.loads(provenance_path.read_text(encoding="utf-8"))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    exposed: str | None = None
    for run in sarif.get("runs", []) if isinstance(sarif, dict) else []:
        driver = ((run or {}).get("tool") or {}).get("driver") if isinstance(run, dict) else None
        candidate = driver.get("version") if isinstance(driver, dict) else None
        if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", candidate):
            exposed = candidate
            break
    value["engine_version"] = exposed
    value["engine_version_status"] = "exposed" if exposed is not None else "not_exposed"
    provenance_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def validate(path: Path, schema_path: Path = SCHEMA, *, require_ready: bool = True) -> list[str]:
    try:
        value = validate_file(path, schema_path)
    except (OSError, SchemaError) as exc:
        return [f"invalid Snyk provenance: {exc}"]
    errors = _private_values(value)
    if not isinstance(value.get("captured_at"), str) or not value["captured_at"].endswith("Z"):
        errors.append("Snyk provenance capture time must be UTC")
    unknown_top_level = set(value) - ALLOWED_TOP_LEVEL
    if unknown_top_level:
        errors.append(f"Snyk provenance contains non-allowlisted fields: {sorted(unknown_top_level)}")
    scan = value.get("scan")
    if isinstance(scan, dict):
        unknown_scan = set(scan) - ALLOWED_SCAN_FIELDS
        if unknown_scan:
            errors.append(f"Snyk scan facts contain non-allowlisted fields: {sorted(unknown_scan)}")
    if value.get("tool") != "snyk-code":
        errors.append("Snyk provenance has the wrong tool")
    if value.get("account_tier") is not None or value.get("account_tier_status") != "not_exposed":
        errors.append("Snyk account tier must remain explicitly not exposed")
    engine_status = value.get("engine_version_status")
    if (engine_status == "exposed") != isinstance(value.get("engine_version"), str):
        errors.append("Snyk engine version/status are inconsistent")
    if engine_status == "not_exposed" and value.get("engine_version") is not None:
        errors.append("Snyk engine version must be null when not exposed")
    if require_ready:
        expected = _vendor()
        if value.get("cli_version") != expected.get("cli_version"):
            errors.append("Snyk provenance CLI version is not release-pinned")
        if value.get("binary_sha256") != expected.get("binary_sha256"):
            errors.append("Snyk provenance binary hash is not release-pinned")
        if value.get("authenticated") is not True:
            errors.append("Snyk provenance is not authenticated")
        if value.get("consent_confirmed") is not True:
            errors.append("Snyk provenance lacks written consent")
        if value.get("cache_isolated") is not True:
            errors.append("Snyk cache is not isolated")
    return errors


def validate_artifacts(directory: Path) -> list[str]:
    """Reject identity/secrets/path leaks in retained Snyk metadata.

    The copied source tree is deliberately excluded: source filenames and
    vulnerable source text are benchmark input, not scanner provenance.
    """
    errors: list[str] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(directory)
        if len(relative.parts) >= 2 and relative.parts[0:2] == ("source-scope", "tree"):
            continue
        if relative.as_posix() == "SHA256SUMS":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"Snyk artifact cannot be inspected: {relative}: {exc}")
            continue
        if path.suffix in {".json", ".jsonl", ".sarif"}:
            if path.name == "snyk-provenance.json":
                continue
            if path.suffix == ".jsonl":
                documents = []
                for line_number, line in enumerate(text.splitlines(), 1):
                    if not line.strip():
                        continue
                    try:
                        documents.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        errors.append(f"Snyk artifact {relative} line {line_number} is invalid JSON: {exc}")
            else:
                try:
                    documents = [json.loads(text)]
                except json.JSONDecodeError as exc:
                    errors.append(f"Snyk artifact {relative} is invalid JSON: {exc}")
                    documents = []
            for document in documents:
                errors.extend(
                    f"{relative}: {error}"
                    for error in _private_values(document, allow_safe_relative_paths=True)
                )
        if relative.parts == ("source-scope", "source-scope.json"):
            errors.extend(f"{relative}: {error}" for error in verify_source_scope(path))
        if PRIVATE_TEXT_RE.search(text) or _private_text_assignments(text):
            errors.append(f"Snyk artifact contains identity, secret, or private-path data: {relative}")
        if _private_query_urls(text):
            errors.append(f"Snyk artifact contains a sensitive URL query parameter: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("create")
    make.add_argument("--output", type=Path, required=True)
    make.add_argument("--cli-version")
    make.add_argument("--binary-sha256")
    make.add_argument("--authenticated", choices=("true", "false"), required=True)
    make.add_argument("--consent-confirmed", choices=("true", "false"), required=True)
    make.add_argument("--cache-isolated", choices=("true", "false"), required=True)
    enrich = sub.add_parser("enrich")
    enrich.add_argument("--provenance", type=Path, required=True)
    enrich.add_argument("--sarif", type=Path, required=True)
    check = sub.add_parser("validate")
    check.add_argument("--provenance", type=Path, required=True)
    check.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    if args.action == "create":
        create(
            args.output,
            cli_version=args.cli_version,
            binary_sha256=args.binary_sha256,
            authenticated=args.authenticated == "true",
            consent_confirmed=args.consent_confirmed == "true",
            cache_isolated=args.cache_isolated == "true",
        )
        return 0
    if args.action == "enrich":
        enrich_engine_version(args.provenance, args.sarif)
        return 0
    errors = validate(args.provenance, require_ready=not args.allow_incomplete)
    for error in errors:
        print(f"ERROR: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
