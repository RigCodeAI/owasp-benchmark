#!/usr/bin/env python3
"""Create and verify immutable run manifests and SHA256SUMS files."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from schema import SchemaError, load_schema, validate, validate_file
from validate_sarif import SarifError, validate_file as validate_sarif_file
from source_scope import verify as verify_source_scope
from zap_automation import validate_history, validate_coverage
from snyk_provenance import validate as validate_snyk_provenance, validate_artifacts as validate_snyk_artifacts


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
STATUSES = {"PASS", "FAILED_ENV", "FAILED_SCAN", "INVALID_OUTPUT", "INCOMPLETE_COVERAGE", "NOT_RUN"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_files(directory: Path) -> list[Path]:
    return sorted(
        path.relative_to(directory)
        for path in directory.rglob("*")
        if path.is_file() and path.relative_to(directory) not in {Path("manifest.json"), Path("SHA256SUMS")}
    )


def write_checksums(directory: Path) -> Path:
    """Write checksums for every file in *directory*, excluding SHA256SUMS."""
    output = directory / "SHA256SUMS"
    lines = []
    for relative in sorted(
        path.relative_to(directory)
        for path in directory.rglob("*")
        if path.is_file() and path.relative_to(directory) != Path("SHA256SUMS")
    ):
        lines.append(f"{sha256_file(directory / relative)}  {relative.as_posix()}")
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return output


def verify_checksums(directory: Path) -> list[str]:
    path = directory / "SHA256SUMS"
    if not path.is_file():
        return ["missing SHA256SUMS"]
    errors: list[str] = []
    listed: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split("  ", 1)
        if len(fields) != 2 or len(fields[0]) != 64:
            errors.append(f"SHA256SUMS line {line_number}: invalid entry")
            continue
        digest, name = fields
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"SHA256SUMS line {line_number}: unsafe path {name}")
            continue
        normalized_name = relative.as_posix()
        if normalized_name in listed:
            errors.append(f"SHA256SUMS line {line_number}: duplicate entry {name}")
        listed.add(normalized_name)
        target = directory / relative
        if not target.is_file():
            errors.append(f"SHA256SUMS line {line_number}: missing {name}")
        elif sha256_file(target) != digest:
            errors.append(f"SHA256SUMS line {line_number}: hash mismatch for {name}")
    expected = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file() and path.relative_to(directory) != Path("SHA256SUMS")
    }
    for missing in sorted(expected - listed):
        errors.append(f"SHA256SUMS: unlisted file {missing}")
    for extra in sorted(listed - expected):
        errors.append(f"SHA256SUMS: unexpected entry {extra}")
    return errors


def _safe_manifest_path(value: object) -> bool:
    if not isinstance(value, str) or not value or Path(value).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\"):
        return False
    return ".." not in Path(value).parts and not any(token in value for token in ("/Users/", "/private/", "/home/"))


def _private_string(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return (
        value.startswith(("/", "file://"))
        or re.match(r"^[A-Za-z]:[\\/]", value) is not None
        or value.startswith("\\\\")
        or "/Users/" in value
        or "/private/" in value
        or "/home/" in value
    )


def _check_public_fields(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            errors.extend(_check_public_fields(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_check_public_fields(item, f"{path}[{index}]"))
    elif _private_string(value):
        errors.append(f"{path} contains an absolute/private path")
    return errors


def _validate_configuration(directory: Path, configuration: Any) -> list[str]:
    if not isinstance(configuration, dict):
        return ["configuration must be an object"]
    path = configuration.get("path")
    digest = configuration.get("sha256")
    if path is None:
        return [] if digest is None else ["configuration hash has no path"]
    if not _safe_manifest_path(path):
        return ["configuration path is absolute or unsafe"]
    if not isinstance(digest, str) or len(digest) != 64:
        return ["configuration sha256 is missing or malformed"]
    if str(path).startswith("external:"):
        evidence_path = configuration.get("evidence_path")
        if evidence_path is None:
            return []
        if not _safe_manifest_path(evidence_path):
            return ["external configuration evidence path is absolute or unsafe"]
        evidence_file = directory / evidence_path
        if not evidence_file.is_file():
            return [f"external configuration evidence missing: {evidence_path}"]
        try:
            evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [f"invalid external configuration evidence: {exc}"]

        if not isinstance(evidence, dict) or evidence.get("sha256") != digest:
            return ["external configuration evidence hash mismatch"]
        return []
    config_file = directory / path
    if not config_file.is_file():
        return [f"configuration artifact missing: {path}"]
    return [] if sha256_file(config_file) == digest else [f"configuration hash mismatch: {path}"]


def _git_commit(path: Path) -> str:
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def _load_json(path: Path | None, default: Any) -> Any:
    if path is None:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A failed preflight may not have been able to create source-scope
        # metadata.  The runner must still emit a manifest and checksums; the
        # failed status remains visible and PASS validation still requires a
        # verified scope.
        return default


def create_manifest(
    directory: Path,
    *,
    run_id: str,
    tool: str,
    method: str,
    benchmark_commit: str,
    harness_commit: str,
    command: list[str],
    status: str,
    exit_code: int | None,
    started_at: str,
    tool_version: Any,
    engine_version: Any = None,
    config: dict[str, Any] | None = None,
    source_scope: dict[str, Any] | None = None,
    coverage_reference: str | None = None,
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"invalid run status {status!r}")
    for name, value in (("benchmark_commit", benchmark_commit), ("harness_commit", harness_commit)):
        if not isinstance(value, str) or len(value) != 40 or any(char not in "0123456789abcdef" for char in value.lower()):
            raise ValueError(f"{name} must be a 40-character commit SHA")
    if method == "sast" and status == "PASS" and not source_scope:
        raise ValueError("SAST manifests require exact source_scope metadata")
    if isinstance(source_scope, dict) and "scope_path" in source_scope:
        source_scope = {
            "path": source_scope.get("scope_path"),
            "source_path": source_scope.get("source_path"),
            "source_commit": source_scope.get("source_commit"),
            "tree_sha256": source_scope.get("tree_sha256"),
            "manifest_sha256": source_scope.get("manifest_sha256"),
            "excluded": source_scope.get("excluded", []),
            "manifest": source_scope.get("manifest", "source-scope.json"),
        }
    if not isinstance(run_id, str) or not run_id or "/" in run_id or "\\" in run_id:
        raise ValueError("run_id must be a simple non-empty identifier")
    if config is None:
        config = {"path": None, "sha256": None}
    else:
        config = dict(config)
        if config.get("sha256") == "":
            config["sha256"] = None
        config_path = config.get("path")
        if config_path:
            config_path_obj = Path(str(config_path))
            if config_path_obj.is_absolute():
                config["path"] = "external:" + config_path_obj.name
                if config_path_obj.is_file():
                    config["sha256"] = sha256_file(config_path_obj)
            else:
                config["path"] = str(config_path)
    environment = {
        "captured_at": utc_now(),
        "platform": platform.platform(),
        "os": platform.system(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
    }
    # Keep environment evidence standalone and write it before enumerating
    # artifacts. It intentionally contains no checksum fields, so including
    # it in both the artifact list and SHA256SUMS cannot create a cycle.
    environment_path = directory / "environment.json"
    environment_path.write_text(json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifact_items = []
    for relative in _relative_files(directory):
        path = directory / relative
        artifact_items.append({"path": relative.as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "tool": tool,
        "method": method,
        "status": status,
        "started_at": started_at,
        "finished_at": utc_now(),
        "benchmark_commit": benchmark_commit,
        "harness_commit": harness_commit,
        "command": command,
        "tool_version": tool_version,
        "engine_version": engine_version,
        "configuration": config,
        "environment": environment,
        "exit_code": exit_code,
        "source_scope": source_scope,
        "coverage_reference": coverage_reference,
        "artifacts": artifact_items,
        "checksums": "SHA256SUMS",
    }
    output = directory / "manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_checksums(directory)
    return manifest


def validate_run(directory: Path, schema_dir: Path = SCHEMAS) -> list[str]:
    errors: list[str] = []
    manifest_path = directory / "manifest.json"
    try:
        manifest = validate_file(manifest_path, schema_dir / "run-manifest.schema.json")
    except (SchemaError, OSError) as exc:
        return [str(exc)]
    errors.extend(verify_checksums(directory))
    errors.extend(_validate_configuration(directory, manifest.get("configuration")))
    errors.extend(_check_public_fields(manifest))
    environment_path = directory / "environment.json"
    if not environment_path.is_file():
        errors.append("run missing environment.json")
    else:
        try:
            environment_value = validate_file(environment_path, schema_dir / "environment.schema.json")
            if environment_value != manifest.get("environment"):
                errors.append("environment.json does not exactly match manifest environment")
            errors.extend(_check_public_fields(environment_value, "$.environment.json"))
        except (SchemaError, OSError) as exc:
            errors.append(f"environment.json: {exc}")
    listed = {item.get("path") for item in manifest.get("artifacts", []) if isinstance(item, dict)}
    actual = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file() and path.relative_to(directory) not in {Path("manifest.json"), Path("SHA256SUMS")}
    }
    if listed != actual:
        for missing in sorted(actual - listed):
            errors.append(f"manifest does not list artifact: {missing}")
        for extra in sorted(listed - actual):
            errors.append(f"manifest lists missing artifact: {extra}")
    for item in manifest.get("artifacts", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            errors.append("manifest artifact has no path")
            continue
        path = directory / item["path"]
        if not path.is_file():
            errors.append(f"manifest artifact missing: {item['path']}")
        elif item.get("sha256") != sha256_file(path):
            errors.append(f"manifest artifact hash mismatch: {item['path']}")
        elif item.get("bytes") != path.stat().st_size:
            errors.append(f"manifest artifact size mismatch: {item['path']}")
        if Path(item["path"]).is_absolute() or ".." in Path(item["path"]).parts:
            errors.append(f"manifest artifact path is unsafe: {item['path']}")
    status = manifest.get("status")
    if str(manifest.get("tool", "")).lower() == "snyk-code":
        provenance_path = directory / "snyk-provenance.json"
        if not provenance_path.is_file():
            errors.append("Snyk run missing snyk-provenance.json")
        else:
            errors.extend(validate_snyk_provenance(provenance_path, require_ready=status == "PASS"))
        configuration = manifest.get("configuration") or {}
        if configuration.get("path") != "snyk-provenance.json":
            errors.append("Snyk manifest must bind snyk-provenance.json as configuration")
        elif provenance_path.is_file() and configuration.get("sha256") != sha256_file(provenance_path):
            errors.append("Snyk configuration hash does not match provenance")
        errors.extend(validate_snyk_artifacts(directory))
        for scope_metadata in directory.rglob("source-scope.json"):
            errors.extend(verify_source_scope(scope_metadata))
    if status == "PASS":
        exit_code = manifest.get("exit_code")
        accepted_exit_codes = {0, 1} if str(manifest.get("tool", "")).lower() in {"semgrep", "snyk-code", "snyk"} else {0}
        if not isinstance(exit_code, int) or exit_code not in accepted_exit_codes:
            errors.append(f"PASS run has unacceptable exit code: {exit_code!r}")
        command_file = directory / "command.txt"
        if not command_file.is_file() or not command_file.read_text(encoding="utf-8").strip():
            errors.append("PASS run missing command.txt")
        raw = directory / "raw.sarif"
        if not raw.is_file():
            errors.append("PASS run missing raw.sarif")
        else:
            try:
                validate_sarif_file(raw)
            except SarifError as exc:
                errors.append(f"raw.sarif: {exc}")
        for required in ("normalized.jsonl", "normalization.json", "score.json"):
            if not (directory / required).is_file():
                errors.append(f"PASS run missing {required}")
        normalization_path = directory / "normalization.json"
        if normalization_path.is_file():
            try:
                validate_file(normalization_path, schema_dir / "normalization.schema.json")
            except (SchemaError, OSError) as exc:
                errors.append(f"normalization.json: {exc}")
        if manifest.get("method") == "sast":
            source_scope = manifest.get("source_scope")
            if not isinstance(source_scope, dict) or source_scope.get("path") != "tree" or source_scope.get("manifest") != "source-scope.json":
                errors.append("PASS SAST run lacks exact tree source scope")
            if isinstance(source_scope, dict):
                if source_scope.get("source_commit") != manifest.get("benchmark_commit"):
                    errors.append("source scope commit does not match benchmark commit")
                if not _safe_manifest_path(source_scope.get("source_path")) or "/" in str(source_scope.get("source_path")):
                    errors.append("source scope path must be a checkout basename")
            scope_files = list(directory.rglob("source-scope.json"))
            if len(scope_files) != 1:
                errors.append("PASS SAST run must contain exactly one source-scope.json")
            elif str(manifest.get("tool", "")).lower() != "snyk-code":
                errors.extend(verify_source_scope(scope_files[0]))
        if manifest.get("method") == "dast":
            required_dast = ("zap-report.json", "coverage.json", "seed-boundary.json", "zap-history.json", "passive-scan.json", "active-scan.json", "zap-runtime.json")
            for required in required_dast:
                if not (directory / required).is_file():
                    errors.append(f"PASS DAST run missing {required}")
            history = [directory / name for name in ("zap-history.json", "history.json") if (directory / name).is_file()]
            if len(history) != 1:
                errors.append("PASS DAST run requires copied history evidence")
            runtime = directory / "zap-runtime.json"
            if runtime.is_file():
                try:
                    runtime_value = json.loads(runtime.read_text(encoding="utf-8"))
                    if not isinstance(runtime_value.get("version"), (str, dict)) or not runtime_value.get("addons"):
                        errors.append("ZAP runtime evidence lacks version/add-ons")
                    if not isinstance(runtime_value.get("image_digest"), str) or not runtime_value["image_digest"].startswith("sha256:"):
                        errors.append("ZAP runtime evidence lacks image digest")
                    if not isinstance(runtime_value.get("platform_digest"), str) or not runtime_value["platform_digest"].startswith("sha256:"):
                        errors.append("ZAP runtime evidence lacks platform image digest")
                    addons_hash = runtime_value.get("addons_sha256")
                    addons = runtime_value.get("addons")
                    expected_addons_hash = hashlib.sha256(
                        json.dumps(addons, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()
                    if addons_hash != expected_addons_hash:
                        errors.append("ZAP add-on evidence hash mismatch")
                    configuration = manifest.get("configuration") or {}
                    if configuration.get("path") == "automation-plan.yaml":
                        if runtime_value.get("automation_plan_sha256") != configuration.get("sha256"):
                            errors.append("ZAP automation-plan hash does not match manifest configuration")
                    if runtime_value.get("target_url") != "http://benchmark:8000/benchmark":
                        errors.append("ZAP runtime evidence target URL is not the pinned benchmark URL")
                except json.JSONDecodeError:
                    errors.append("invalid zap-runtime.json")
            native = directory / "zap-report.json"
            if native.is_file():
                try:
                    if not isinstance(json.loads(native.read_text(encoding="utf-8")), dict):
                        errors.append("zap-report.json must be a JSON object")
                except json.JSONDecodeError:
                    errors.append("invalid zap-report.json")
            coverage_path = directory / "coverage.json"
            if coverage_path.is_file():
                errors.extend(validate_coverage(coverage_path, 1230))
            history_path = directory / "zap-history.json"
            if history_path.is_file():
                errors.extend(validate_history(history_path, 1230, coverage_path if coverage_path.is_file() else None))
            for evidence_name in ("seed-boundary.json", "passive-scan.json", "active-scan.json"):
                evidence_path = directory / evidence_name
                if evidence_path.is_file():
                    try:
                        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                        if evidence_name == "seed-boundary.json":
                            if not isinstance(evidence.get("seed_request_count"), int) or not isinstance(evidence.get("unique_case_ids"), int):
                                errors.append("seed-boundary.json lacks request and unique-case evidence")
                        elif evidence.get("completed") is not True:
                            errors.append(f"{evidence_name} is not marked completed")
                    except json.JSONDecodeError:
                        errors.append(f"invalid {evidence_name}")
            coverage_ref = manifest.get("coverage_reference")
            if not isinstance(coverage_ref, str) or not _safe_manifest_path(coverage_ref) or not (directory / coverage_ref).is_file():
                errors.append("PASS DAST run has invalid coverage reference")
    coverage_ref = manifest.get("coverage_reference")
    if coverage_ref is not None:
        if not _safe_manifest_path(coverage_ref) or not (directory / coverage_ref).is_file():
            errors.append("coverage_reference is missing or unsafe")
    findings = directory / "normalized.jsonl"
    if findings.is_file():
        for line_number, line in enumerate(findings.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                validate(value, load_schema(schema_dir / "finding.schema.json"))
            except (json.JSONDecodeError, SchemaError) as exc:
                errors.append(f"normalized.jsonl line {line_number}: {exc}")
    elif manifest.get("status") == "PASS":
        errors.append("PASS run missing normalized.jsonl")
    for name in ("score.json", "coverage.json"):
        path = directory / name
        if path.is_file():
            try:
                validate_file(path, schema_dir / ("score.schema.json" if name == "score.json" else "coverage.schema.json"))
            except (SchemaError, OSError) as exc:
                errors.append(f"{name}: {exc}")
        elif name == "score.json" and manifest.get("status") == "PASS":
            errors.append("PASS run missing score.json")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create")
    create.add_argument("--artifact-dir", type=Path, required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--tool", required=True)
    create.add_argument("--method", choices=("sast", "dast", "iast"), required=True)
    create.add_argument("--benchmark-commit", required=True)
    create.add_argument("--harness-commit", required=True)
    create.add_argument("--status", choices=sorted(STATUSES), required=True)
    create.add_argument("--exit-code", type=int)
    create.add_argument("--started-at", required=True)
    create.add_argument("--command", action="append", default=[])
    create.add_argument("--tool-version-file", type=Path)
    create.add_argument("--tool-version", default="unknown")
    create.add_argument("--engine-version")
    create.add_argument("--config-path")
    create.add_argument("--config-sha256")
    create.add_argument("--config-evidence")
    create.add_argument("--source-scope", type=Path)
    create.add_argument("--coverage-reference")
    verify = sub.add_parser("verify")
    verify.add_argument("--artifact-dir", type=Path, required=True)
    verify.add_argument("--schema-dir", type=Path, default=SCHEMAS)
    args = parser.parse_args()
    if args.action == "create":
        directory = args.artifact_dir.resolve()
        directory.mkdir(parents=True, exist_ok=True)
        version: Any = args.tool_version
        if args.tool_version_file and args.tool_version_file.is_file():
            version = args.tool_version_file.read_text(encoding="utf-8").strip()
        config = {
            "path": args.config_path or None,
            "sha256": args.config_sha256 or None,
            "evidence_path": args.config_evidence or None,
        }
        source_scope = _load_json(args.source_scope, None)
        if source_scope is not None and isinstance(source_scope, dict):
            source_scope = {
                "path": source_scope.get("scope_path", source_scope.get("path")),
                "source_path": source_scope.get("source_path"),
                "source_commit": source_scope.get("source_commit"),
                "tree_sha256": source_scope.get("tree_sha256"),
                "manifest_sha256": source_scope.get("manifest_sha256"),
                "excluded": source_scope.get("excluded", []),
                "manifest": args.source_scope.name if args.source_scope else None,
            }
        harness = args.harness_commit
        create_manifest(
            directory,
            run_id=args.run_id,
            tool=args.tool,
            method=args.method,
            benchmark_commit=args.benchmark_commit,
            harness_commit=harness,
            command=args.command,
            status=args.status,
            exit_code=args.exit_code,
            started_at=args.started_at,
            tool_version=version,
            engine_version=args.engine_version,
            config=config,
            source_scope=source_scope,
            coverage_reference=args.coverage_reference,
        )
        errors = validate_run(directory)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        return 0
    errors = validate_run(args.artifact_dir.resolve(), args.schema_dir.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Run artifacts verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
