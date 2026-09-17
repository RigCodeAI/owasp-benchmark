#!/bin/sh
set -u

if [ "$#" -ne 2 ]; then
  echo "usage: $0 BENCHMARK_DIR ARTIFACT_DIR" >&2
  exit 2
fi
target=$(CDPATH= cd -- "$1" && pwd)
mkdir -p "$2"
artifacts=$(CDPATH= cd -- "$2" && pwd)
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
suite=${CODEQL_SUITE:-}
run_id=${RUN_ID:-$(basename "$artifacts")}
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
benchmark_commit=$(git -C "$target" rev-parse HEAD 2>/dev/null || true)
harness_commit=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)
scope_dir=${SOURCE_SCOPE_DIR:-"$artifacts/source-scope"}
database_parent=${CODEQL_DB_DIR:-}
database="$database_parent/database"
query_pack=${CODEQL_QUERY_PACK_PATH:-}
query_sha256=
bundle_archive_sha256=${CODEQL_BUNDLE_ARCHIVE_SHA256:-84e5f9d804ae58c41930c33cd61cbeffdbca86689fc85f2f89a2ab0eec433bd6}
bundle_archive_path=${CODEQL_BUNDLE_ARCHIVE_PATH:-}
expected_codeql_version=${CODEQL_VERSION:-2.27.0}
query_pack_version=${CODEQL_QUERY_PACK_VERSION:-1.8.10}
status=FAILED_ENV
exit_code=127
printf '%s\n' "unavailable" >"$artifacts/version.json"
tool_version_file="$artifacts/version.json"
printf '%s\n' "codeql database create <external-db> --language=python --source-root=<source-scope/tree> --build-mode=none" \
  "codeql database analyze <external-db> <pinned-suite> --format=sarifv2.1.0 --output=raw.sarif" >"$artifacts/command.txt"
finish() {
  python3 "$repo_root/tools/run_manifest.py" create --artifact-dir "$artifacts" --run-id "$run_id" \
    --tool codeql --method sast --benchmark-commit "${benchmark_commit:-0000000000000000000000000000000000000000}" \
    --harness-commit "${harness_commit:-0000000000000000000000000000000000000000}" \
    --status "$status" --exit-code "$exit_code" --started-at "$started_at" \
    --command "codeql database create <external-db> --language=python --source-root=<source-scope/tree> --build-mode=none" \
    --command "codeql database analyze <external-db> <pinned-suite> --format=sarifv2.1.0 --output=raw.sarif" \
    --tool-version-file "$tool_version_file" --config-path "$query_pack" --config-sha256 "${query_sha256:-}" \
    --source-scope "$scope_dir/source-scope.json"
}
suite_sha256=

release_archive_sha256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bundle_archive_sha256"])' "$repo_root/configs/vendors/codeql.json")
release_pack_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["query_pack_version"])' "$repo_root/configs/vendors/codeql.json")
release_cli_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cli_version"])' "$repo_root/configs/vendors/codeql.json")
if [ "$bundle_archive_sha256" != "$release_archive_sha256" ] || [ "$query_pack_version" != "$release_pack_version" ] || [ "$expected_codeql_version" != "$release_cli_version" ]; then
  printf '%s\n' "CodeQL bundle, CLI, and query-pack settings must match the release-frozen configuration" >"$artifacts/stderr.log"; finish; exit 1
fi

if [ -z "$benchmark_commit" ] || [ -z "$harness_commit" ]; then
  printf '%s\n' "Unable to determine benchmark or harness commit" >"$artifacts/stderr.log"; finish; exit 1
fi
python3 "$repo_root/tools/source_scope.py" prepare --source "$target" --output "$scope_dir" --source-commit "$benchmark_commit" \
  >"$artifacts/source-scope.stdout.log" 2>"$artifacts/source-scope.stderr.log" || { exit_code=1; finish; exit 1; }
bundle_path=${CODEQL_BUNDLE_PATH:-}
if [ -z "$bundle_path" ] || [ ! -d "$bundle_path" ] || [ ! -x "$bundle_path/codeql" ]; then
  printf '%s\n' "CODEQL_BUNDLE_PATH must be an existing bundle root containing executable codeql" >"$artifacts/stderr.log"; finish; exit 1
fi
if [ -z "$suite" ]; then
  query_pack="$bundle_path/qlpacks/codeql/python-queries/$query_pack_version"
fi
if [ -z "$suite" ]; then
  suite="$query_pack/codeql-suites/python-security-extended.qls"
fi
if [ -z "$bundle_archive_path" ] || [ ! -f "$bundle_archive_path" ]; then
  printf '%s\n' "CODEQL_BUNDLE_ARCHIVE_PATH must point at the downloaded official bundle archive" >"$artifacts/stderr.log"; finish; exit 1
fi
if [ -z "$database_parent" ] || [ "${database_parent#/}" = "$database_parent" ] || [ ! -d "$(dirname "$database_parent")" ]; then
  printf '%s\n' "CODEQL_DB_DIR must point outside the artifact/release tree" >"$artifacts/stderr.log"; finish; exit 1
fi
database_parent_root=$(CDPATH= cd -- "$(dirname "$database_parent")" 2>/dev/null && pwd || true)
database_parent="$database_parent_root/$(basename "$database_parent")"
case "$database_parent" in
  "$artifacts"|"$artifacts"/*|"$repo_root"|"$repo_root"/*) printf '%s\n' "CODEQL_DB_DIR is inside the artifact/release tree" >"$artifacts/stderr.log"; finish; exit 1 ;;
esac
version_tmp=$(mktemp "${TMPDIR:-/tmp}/codeql-version.XXXXXX")
"$bundle_path/codeql" version --format=json >"$version_tmp" 2>"$artifacts/version.stderr.log"
version_status=$?
if [ "$version_status" -ne 0 ]; then
  printf '%s\n' "unavailable" >"$artifacts/version.json"
  rm -f "$version_tmp"
  exit_code=$version_status; finish; exit "$version_status"
fi
PYTHONPATH="$repo_root/tools" python3 -c 'import json,sys; from pathlib import Path; from codeql_metadata import public_value; Path(sys.argv[2]).write_text(json.dumps(public_value(json.load(open(sys.argv[1]))), sort_keys=True)+"\n")' "$version_tmp" "$tool_version_file" || {
  rm -f "$version_tmp"
  exit_code=1; finish; exit 1
}
rm -f "$version_tmp"
if [ -z "$query_pack" ] || [ ! -e "$query_pack" ]; then
  printf '%s\n' "CODEQL_QUERY_PACK_PATH must point at the frozen query pack" >"$artifacts/stderr.log"; finish; exit 1
fi
if [ -f "$query_pack" ]; then
  query_sha256=$(shasum -a 256 "$query_pack" | awk '{print $1}')
else
  query_sha256=$(python3 -c 'import hashlib,sys; from pathlib import Path; root=Path(sys.argv[1]); h=hashlib.sha256(); [h.update((p.relative_to(root).as_posix()+"\0").encode()+p.read_bytes()+b"\n") for p in sorted(root.rglob("*")) if p.is_file()]; print(h.hexdigest())' "$query_pack")
fi
if [ ! -f "$suite" ]; then
  printf '%s\n' "CODEQL_SUITE must point at the frozen local suite file" >"$artifacts/stderr.log"; finish; exit 1
fi
suite_sha256=$(shasum -a 256 "$suite" | awk '{print $1}')
if ! python3 "$repo_root/tools/codeql_metadata.py" --bundle "$bundle_path" --query-pack "$query_pack" --suite "$suite" \
  --archive "$bundle_archive_path" --archive-sha256 "$bundle_archive_sha256" --query-pack-version "$query_pack_version" \
  --expected-codeql-version "$expected_codeql_version" --output "$artifacts/codeql-metadata.json" \
  >"$artifacts/codeql-metadata.stdout.log" 2>"$artifacts/codeql-metadata.stderr.log"; then
  exit_code=1; status=FAILED_ENV; finish; exit 1
fi
query_sha256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["query_pack"]["sha256"])' "$artifacts/codeql-metadata.json") || {
  exit_code=1; status=FAILED_ENV; finish; exit 1
}
printf '%s\n' "codeql database create <external-db> --language=python --source-root=<source-scope/tree> --build-mode=none" \
  "codeql database analyze <external-db> <pinned-suite> --format=sarifv2.1.0 --output=raw.sarif" >"$artifacts/command.txt"
mkdir -p "$database_parent"
if [ -e "$database" ]; then
  printf '%s\n' "Refusing to replace existing CodeQL database: $database" >"$artifacts/stderr.log"; finish; exit 1
fi
"$bundle_path/codeql" database create "$database" --language=python --source-root="$scope_dir/tree" --build-mode=none \
  >"$artifacts/create.stdout.log" 2>"$artifacts/create.stderr.log"
create_status=$?
if [ "$create_status" -ne 0 ]; then exit_code=$create_status; status=FAILED_SCAN; finish; exit "$create_status"; fi
"$bundle_path/codeql" database analyze "$database" "$suite" --format=sarifv2.1.0 --output="$artifacts/raw.sarif" \
  >"$artifacts/stdout.log" 2>"$artifacts/stderr.log"
scan_status=$?
exit_code=$scan_status
if [ ! -s "$artifacts/raw.sarif" ] || ! python3 "$repo_root/tools/validate_sarif.py" --input "$artifacts/raw.sarif" \
  >"$artifacts/raw-validation.log" 2>&1; then
  status=INVALID_OUTPUT; finish; exit 1
fi
if [ "$scan_status" -ne 0 ]; then status=FAILED_SCAN; finish; exit "$scan_status"; fi
if ! python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json"; then status=INVALID_OUTPUT; finish; exit 1; fi
if ! python3 "$repo_root/tools/score.py" --expected "$target/expectedresults-0.1.csv" --findings "$artifacts/normalized.jsonl" --output "$artifacts/score.json"; then status=INVALID_OUTPUT; finish; exit 1; fi
status=PASS
finish
