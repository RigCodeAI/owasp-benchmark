#!/usr/bin/env python3
"""Create and verify an immutable scanner-neutral SAST source scope.

The scanner receives only ``<scope>/tree``.  The manifest is deliberately a
sibling of that tree so it can never become scanner input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".tox", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "results", "runs", "artifacts",
    ".work", "build", "dist", "coverage", "htmlcov", "codeql-db", ".codeql",
    ".scannerwork", ".semgrep", ".snyk", "scripts", "scanner", "scanner-scripts",
}
EXCLUDED_FILES = {"SHA256SUMS", "source-scope.json", ".coverage"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".sarif", ".jsonl"}


def _ignored(relative: Path, is_dir: bool) -> bool:
    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return True
    if not is_dir and (relative.name in EXCLUDED_FILES or relative.suffix in EXCLUDED_SUFFIXES):
        return True
    if not is_dir and relative.name.lower() in {"scanner.py", "scanner.sh", "run-scanner.py", "scan.py"}:
        return True
    return not is_dir and relative.name in {"expectedresults-0.1.csv", "benchmark.lock.json"}


def _tree_files(root: Path) -> list[Path]:
    return sorted(path.relative_to(root) for path in root.rglob("*") if path.is_file())


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hash(root: Path) -> tuple[str, list[dict[str, Any]]]:
    files = []
    for relative in _tree_files(root):
        path = root / relative
        files.append({"path": relative.as_posix(), "sha256": _file_hash(path), "bytes": path.stat().st_size})
    canonical = "".join(f"{item['sha256']}  {item['path']}\n" for item in files).encode()
    return hashlib.sha256(canonical).hexdigest(), files


def _manifest_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def prepare(source: Path, destination: Path, *, source_commit: str | None = None) -> dict[str, Any]:
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_dir():
        raise ValueError(f"source is not a directory: {source}")
    if destination == source or source in destination.parents:
        raise ValueError("source scope destination must be outside the benchmark source")
    if not source_commit or not COMMIT_RE.fullmatch(source_commit):
        raise ValueError("source_commit must be a 40-character lowercase commit SHA")
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            raise ValueError(f"refusing to replace non-empty source scope: {destination}")
    else:
        destination.mkdir(parents=True)
    tree = destination / "tree"
    tree.mkdir()
    ignored: list[str] = []
    for current, dirs, files in os.walk(source):
        current_path = Path(current)
        relative_dir = current_path.relative_to(source)
        kept_dirs = []
        for name in sorted(dirs):
            relative = relative_dir / name
            if _ignored(relative, True):
                ignored.append(relative.as_posix() + "/")
            else:
                kept_dirs.append(name)
        dirs[:] = kept_dirs
        output_dir = tree / relative_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            relative = relative_dir / name
            if _ignored(relative, False):
                ignored.append(relative.as_posix())
                continue
            output = tree / relative
            shutil.copy2(current_path / name, output)
    digest, files = tree_hash(tree)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "source_path": source.name,
        "source_commit": source_commit,
        "scope_path": "tree",
        "manifest_path": "source-scope.json",
        "tree_sha256": digest,
        "files": files,
        "excluded": sorted(ignored),
    }
    payload["manifest_sha256"] = _manifest_hash(payload)
    (destination / "source-scope.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return payload


def _safe_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return False
    return ".." not in Path(value).parts and "\\" not in value


def verify(manifest_path: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent
    if manifest_path.name != "source-scope.json":
        errors.append("source scope metadata must be named source-scope.json")
    if not manifest_path.is_file():
        return ["missing source-scope.json"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid source-scope manifest: {exc}"]
    if manifest.get("schema_version") != 1:
        errors.append("unsupported source-scope schema version")
    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit):
        errors.append("source_commit is not a 40-character lowercase SHA")
    if not _safe_relative(manifest.get("source_path")):
        errors.append("source_path must be a safe relative checkout name")
    if manifest.get("scope_path") != "tree":
        errors.append("scope_path must be tree")
    if manifest.get("manifest_path") != "source-scope.json":
        errors.append("manifest_path must be source-scope.json")
    tree = root / "tree"
    if not tree.is_dir():
        errors.append("missing scanner source tree")
    # Only the scanner tree and its sibling metadata are permitted. This makes
    # a generated report or copied metadata fail closed instead of being hidden.
    for child in root.iterdir():
        if child.name not in {"tree", "source-scope.json"}:
            errors.append(f"unexpected source-scope entry: {child.name}")
    recorded = manifest.get("files")
    if not isinstance(recorded, list):
        errors.append("files must be a list")
        recorded = []
    recorded_paths: set[str] = set()
    for item in recorded:
        if not isinstance(item, dict) or not _safe_relative(item.get("path")):
            errors.append("source file record has unsafe path")
            continue
        relative = str(item["path"])
        if relative in recorded_paths:
            errors.append(f"duplicate source file record: {relative}")
        recorded_paths.add(relative)
        path = tree / relative
        if not path.is_file():
            errors.append(f"missing source file: {relative}")
        elif item.get("sha256") != _file_hash(path) or item.get("bytes") != path.stat().st_size:
            errors.append(f"source file hash/size mismatch: {relative}")
    actual_paths = {path.as_posix() for path in _tree_files(tree)} if tree.is_dir() else set()
    for extra in sorted(actual_paths - recorded_paths):
        errors.append(f"unlisted source file: {extra}")
    canonical = "".join(
        f"{item.get('sha256')}  {item.get('path')}\n" for item in recorded if isinstance(item, dict)
    ).encode()
    if hashlib.sha256(canonical).hexdigest() != manifest.get("tree_sha256"):
        errors.append("source tree hash mismatch")
    payload = dict(manifest)
    manifest_digest = payload.pop("manifest_sha256", None)
    if _manifest_hash(payload) != manifest_digest:
        errors.append("source-scope manifest hash mismatch")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--source", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--source-commit", required=True)
    check = sub.add_parser("verify")
    check.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "prepare":
        result = prepare(args.source, args.output, source_commit=args.source_commit)
        print(json.dumps({"tree_sha256": result["tree_sha256"], "manifest_sha256": result["manifest_sha256"]}, sort_keys=True))
        return 0
    errors = verify(args.manifest)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Source scope verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
