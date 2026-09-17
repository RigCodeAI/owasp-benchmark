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
rules=
rules_sha256=
rules_manifest=
snapshot_sha256=
snapshot_rule_count=
status=FAILED_ENV
exit_code=127
printf '%s\n' "unavailable" >"$artifacts/version.txt"
printf '%s\n' "semgrep scan --config <frozen-rules> --sarif --output raw.sarif <source-scope/tree>" >"$artifacts/command.txt"
finish() {
  config_args=
  if [ -n "$rules" ] && [ -n "$rules_sha256" ] && [ -f "$artifacts/semgrep-provenance.json" ]; then
    config_args="--config-path $rules --config-sha256 $rules_sha256 --config-evidence semgrep-provenance.json"
  fi
  python3 "$repo_root/tools/run_manifest.py" create \
    --artifact-dir "$artifacts" --run-id "$run_id" --tool semgrep --method sast \
    --benchmark-commit "${benchmark_commit:-0000000000000000000000000000000000000000}" \
    --harness-commit "${harness_commit:-0000000000000000000000000000000000000000}" \
    --status "$status" --exit-code "$exit_code" --started-at "$started_at" \
    --command "semgrep scan --config <frozen-rules> --sarif --output raw.sarif <source-scope/tree>" \
    --tool-version-file "$artifacts/version.txt" $config_args \
    --source-scope "$scope_dir/source-scope.json"
}
if [ -z "$benchmark_commit" ] || [ -z "$harness_commit" ]; then
  printf '%s\n' "Unable to determine benchmark or harness commit" >"$artifacts/stderr.log"
  finish
  exit 1
fi
python3 "$repo_root/tools/source_scope.py" prepare --source "$target" --output "$scope_dir" --source-commit "$benchmark_commit" \
  >"$artifacts/source-scope.stdout.log" 2>"$artifacts/source-scope.stderr.log" || {
    status=FAILED_ENV; exit_code=1; finish; exit 1;
  }
rules=${SEMGREP_RULES:-}
if [ -n "$rules" ]; then rules_manifest=${SEMGREP_RULES_MANIFEST:-"$rules.manifest.json"}; fi
if [ -z "$rules" ] || [ ! -f "$rules" ] || [ ! -f "$rules_manifest" ]; then
  printf '%s\n' "SEMGREP_RULES must be a frozen local rules file and SEMGREP_RULES_MANIFEST must exist" >"$artifacts/stderr.log"
  finish
  exit 1
fi
snapshot_sha256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["resolved_snapshot"]["sha256"])' "$repo_root/configs/vendors/semgrep.json")
snapshot_rule_count=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["resolved_snapshot"]["rules"])' "$repo_root/configs/vendors/semgrep.json")
if ! python3 "$repo_root/tools/freeze_semgrep.py" verify --rules "$rules" --manifest "$rules_manifest" \
  --expected-sha256 "$snapshot_sha256" --expected-rule-count "$snapshot_rule_count" \
  --provenance-output "$artifacts/semgrep-provenance.json" \
  >"$artifacts/rules-verify.stdout.log" 2>"$artifacts/rules-verify.stderr.log"; then
  finish
  exit 1
fi
rules_sha256=$snapshot_sha256
semgrep --version >"$artifacts/version.txt" 2>"$artifacts/version.stderr.log"
version_status=$?
printf '%s\n' "semgrep scan --config <frozen-rules> --sarif --output raw.sarif <source-scope/tree>" >"$artifacts/command.txt"
if [ "$version_status" -ne 0 ]; then
  exit_code=$version_status; status=FAILED_ENV; finish; exit "$version_status"
fi
semgrep scan --config "$rules" --sarif --output "$artifacts/raw.sarif" "$scope_dir/tree" \
  >"$artifacts/stdout.log" 2>"$artifacts/stderr.log"
scan_status=$?
exit_code=$scan_status
if [ ! -s "$artifacts/raw.sarif" ] || ! python3 "$repo_root/tools/validate_sarif.py" --input "$artifacts/raw.sarif" \
  >"$artifacts/raw-validation.log" 2>&1; then
  status=INVALID_OUTPUT
  finish
  exit 1
fi
# Semgrep returns 1 for a completed scan with findings.  Valid SARIF remains
# a usable run, and the exit code is retained in the manifest.
if [ "$scan_status" -ne 0 ] && [ "$scan_status" -ne 1 ]; then
  status=FAILED_SCAN
  finish
  exit "$scan_status"
fi
if ! python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" \
  --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json"; then
  status=INVALID_OUTPUT; finish; exit 1
fi
if ! python3 "$repo_root/tools/score.py" --expected "$target/expectedresults-0.1.csv" \
  --findings "$artifacts/normalized.jsonl" --output "$artifacts/score.json"; then
  status=INVALID_OUTPUT; finish; exit 1
fi
status=PASS
finish
