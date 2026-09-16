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
run_id=${RUN_ID:-$(basename "$artifacts")}
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
benchmark_commit=$(git -C "$target" rev-parse HEAD 2>/dev/null || true)
harness_commit=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)
scope_dir=${SOURCE_SCOPE_DIR:-"$artifacts/source-scope"}
status=FAILED_ENV
exit_code=127
printf '%s\n' "unavailable" >"$artifacts/version.txt"
printf '%s\n' "snyk code test <source-scope/tree> --sarif-file-output=raw.sarif" >"$artifacts/command.txt"
finish() {
  python3 "$repo_root/tools/run_manifest.py" create --artifact-dir "$artifacts" --run-id "$run_id" \
    --tool snyk-code --method sast --benchmark-commit "${benchmark_commit:-0000000000000000000000000000000000000000}" \
    --harness-commit "${harness_commit:-0000000000000000000000000000000000000000}" \
    --status "$status" --exit-code "$exit_code" --started-at "$started_at" \
    --command "snyk code test <source-scope/tree> --sarif-file-output=raw.sarif" \
    --tool-version-file "$artifacts/version.txt" --source-scope "$scope_dir/source-scope.json"
}
if [ -z "$benchmark_commit" ] || [ -z "$harness_commit" ]; then
  printf '%s\n' "Unable to determine benchmark or harness commit" >"$artifacts/stderr.log"; finish; exit 1
fi
python3 "$repo_root/tools/source_scope.py" prepare --source "$target" --output "$scope_dir" --source-commit "$benchmark_commit" \
  >"$artifacts/source-scope.stdout.log" 2>"$artifacts/source-scope.stderr.log" || { exit_code=1; finish; exit 1; }
snyk --version >"$artifacts/version.txt" 2>"$artifacts/version.stderr.log"
version_status=$?
printf '%s\n' "snyk code test <source-scope/tree> --sarif-file-output=raw.sarif" >"$artifacts/command.txt"
if [ "$version_status" -ne 0 ]; then exit_code=$version_status; finish; exit "$version_status"; fi
snyk code test "$scope_dir/tree" --sarif-file-output="$artifacts/raw.sarif" \
  >"$artifacts/stdout.log" 2>"$artifacts/stderr.log"
scan_status=$?
exit_code=$scan_status
if [ ! -s "$artifacts/raw.sarif" ] || ! python3 "$repo_root/tools/validate_sarif.py" --input "$artifacts/raw.sarif" \
  >"$artifacts/raw-validation.log" 2>&1; then
  status=INVALID_OUTPUT; finish; exit 1
fi
# Snyk documents exit 1 as "findings reported", not a failed scan.
if [ "$scan_status" -ne 0 ] && [ "$scan_status" -ne 1 ]; then status=FAILED_SCAN; finish; exit "$scan_status"; fi
if ! python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json"; then status=INVALID_OUTPUT; finish; exit 1; fi
if ! python3 "$repo_root/tools/score.py" --expected "$target/expectedresults-0.1.csv" --findings "$artifacts/normalized.jsonl" --output "$artifacts/score.json"; then status=INVALID_OUTPUT; finish; exit 1; fi
status=PASS
finish
