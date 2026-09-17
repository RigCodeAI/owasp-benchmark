#!/usr/bin/env python3
"""Capture CodeQL bundle, query-pack, and suite identity for a run."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    elif path.is_dir():
        for item in sorted(p for p in path.rglob("*") if p.is_file()):
            relative = item.relative_to(path).as_posix().encode()
            digest.update(relative + b"\0" + bytes.fromhex(sha256(item)) + b"\n")
    else:
        raise FileNotFoundError(path)
    return digest.hexdigest()


def command_output(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return (result.stdout or result.stderr).strip()


def _qlpack_identity(query_pack: Path) -> tuple[str, str]:
    qlpack = query_pack / "qlpack.yml"
    if not query_pack.is_dir() or not qlpack.is_file():
        raise ValueError("CodeQL query-pack must be a directory containing qlpack.yml")
    text = qlpack.read_text(encoding="utf-8")
    name_match = re.search(r"(?m)^\s*name:\s*([^#\s]+)", text)
    version_match = re.search(r"(?m)^\s*version:\s*([^#\s]+)", text)
    if not name_match or not version_match:
        raise ValueError("qlpack.yml must declare name and version")
    return name_match.group(1), version_match.group(1)


def public_value(value):
    if isinstance(value, dict):
        return {key: public_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [public_value(item) for item in value]
    if isinstance(value, str):
        if value.startswith("/"):
            return Path(value).name
        if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\"):
            return re.split(r"[\\/]", value)[-1]
        value = re.sub(r"/(?:Users|private|home|tmp)/[^\s,;]+", "<private-path>", value)
    return value


def capture(
    bundle: Path | None,
    query_pack: Path | None,
    suite: str,
    output: Path,
    *,
    archive: Path | None = None,
    archive_sha256: str | None = None,
    query_pack_version: str | None = None,
    expected_codeql_version: str = "2.27.0",
) -> dict:
    if bundle is None or not bundle.exists():
        raise ValueError("CodeQL bundle path is required and must exist")
    if not bundle.is_dir() or not (bundle / "codeql").is_file():
        raise ValueError("CodeQL bundle path must be the bundle root containing codeql")
    if query_pack is None or not query_pack.exists():
        raise ValueError("CodeQL query-pack path is required and must exist")
    query_pack_name, parsed_pack_version = _qlpack_identity(query_pack)
    if query_pack_name != "codeql/python-queries":
        raise ValueError(f"unexpected CodeQL query-pack name: {query_pack_name}")
    if archive_sha256 is None or not re.fullmatch(r"[0-9a-f]{64}", archive_sha256):
        raise ValueError("CodeQL bundle archive SHA-256 is required")
    if query_pack_version is None or not query_pack_version.strip():
        raise ValueError("CodeQL query-pack version is required")
    if parsed_pack_version != query_pack_version:
        raise ValueError("query-pack version does not match qlpack.yml")
    if archive is None or not archive.is_file():
        raise ValueError("CodeQL bundle archive file is required")
    actual_archive_sha256 = sha256(archive)
    if actual_archive_sha256 != archive_sha256:
        raise ValueError("CodeQL bundle archive SHA-256 does not match the expected checksum")
    suite_path = Path(suite).resolve()
    query_pack_root = query_pack.resolve()
    if not suite_path.is_file() or suite_path.name != "python-security-extended.qls":
        raise ValueError("CodeQL suite must be the pinned python-security-extended.qls file")
    try:
        suite_path.relative_to(query_pack_root)
    except ValueError as exc:
        raise ValueError("CodeQL suite must be resolved under the pinned query-pack directory") from exc
    # Call the pinned executable when available; absence is recorded as an
    # explicit null rather than silently making up a version.
    executable = bundle / "codeql"
    version = command_output([str(executable), "version", "--format=json"])
    resolved_packs = command_output([str(executable), "resolve", "packs"])
    if not version:
        raise ValueError("CodeQL version command returned no output")
    parsed_version = json.loads(version) if version.startswith("{") else version
    version_value = parsed_version.get("version") if isinstance(parsed_version, dict) else None
    if version_value != expected_codeql_version:
        raise ValueError(f"CodeQL CLI version must be {expected_codeql_version}, got {version_value!r}")
    if not resolved_packs or query_pack_name not in resolved_packs or query_pack_version not in resolved_packs:
        raise ValueError("codeql resolve packs did not report the pinned query pack and version")
    result = {
        "schema_version": 1,
        "bundle": {
            "name": bundle.name,
            "sha256": sha256(bundle),
            "archive_name": archive.name,
            "archive_sha256": actual_archive_sha256,
        },
        "query_pack": {"name": query_pack_name, "version": query_pack_version, "sha256": sha256(query_pack)},
        "suite": {
            "name": suite_path.name,
            "path": suite_path.relative_to(query_pack_root).as_posix(),
            "sha256": sha256(suite_path),
            "query_pack": query_pack_name,
        },
        "codeql_version": public_value(parsed_version),
        "resolved_packs": public_value(resolved_packs),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--query-pack", type=Path, required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--archive-sha256")
    parser.add_argument("--query-pack-version")
    parser.add_argument("--expected-codeql-version", default="2.27.0")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        capture(
            args.bundle,
            args.query_pack,
            args.suite,
            args.output,
            archive=args.archive,
            archive_sha256=args.archive_sha256,
            query_pack_version=args.query_pack_version,
            expected_codeql_version=args.expected_codeql_version,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
