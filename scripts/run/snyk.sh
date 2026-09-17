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
snyk_bin=${SNYK_BIN:-}
snyk_cache=${SNYK_CACHE_PATH:-}
consent=${SNYK_WRITTEN_CONSENT:-}
expected_version=1.1306.3
expected_sha256=6affd215ef52f0eebaddd34e946c64bc8cfb06223387d8e6164a10501910fa92
status=FAILED_ENV
exit_code=127
identity_tmp=
provenance="$artifacts/snyk-provenance.json"
printf '%s\n' "unavailable" >"$artifacts/version.txt"
printf '%s\n' "snyk code test <source-scope/tree> --sarif-file-output=raw.sarif" >"$artifacts/command.txt"
provenance_init_status=0
python3 "$repo_root/tools/snyk_provenance.py" create --output "$provenance" \
  --authenticated false --consent-confirmed "$([ "$consent" = confirmed ] && echo true || echo false)" \
  --cache-isolated false >/dev/null 2>"$artifacts/provenance.stderr.log" || provenance_init_status=$?
cleanup_sensitive() {
  if [ -n "$identity_tmp" ]; then
    rm -f "$identity_tmp"
  fi
}
trap cleanup_sensitive EXIT INT TERM
finish() {
  config_args=
  provenance_sha256=
  provenance_binding_failed=0
  if [ -s "$provenance" ]; then
    provenance_sha256=$(shasum -a 256 "$provenance" 2>/dev/null | awk '{print $1}')
    if ! printf '%s' "$provenance_sha256" | grep -Eq '^[0-9a-f]{64}$'; then
      provenance_binding_failed=1
    fi
    if [ "$provenance_binding_failed" -eq 0 ]; then
      config_args="--config-path snyk-provenance.json --config-sha256 $provenance_sha256"
    fi
  else
    provenance_binding_failed=1
  fi
  if [ "$provenance_binding_failed" -ne 0 ]; then
    printf '%s\n' "Snyk provenance is missing or cannot be hashed; manifest binding is unavailable" >>"$artifacts/stderr.log"
    status=FAILED_ENV
    [ "$exit_code" -eq 0 ] && exit_code=1
  fi
  python3 "$repo_root/tools/run_manifest.py" create --artifact-dir "$artifacts" --run-id "$run_id" \
    --tool snyk-code --method sast --benchmark-commit "${benchmark_commit:-0000000000000000000000000000000000000000}" \
    --harness-commit "${harness_commit:-0000000000000000000000000000000000000000}" \
    --status "$status" --exit-code "$exit_code" --started-at "$started_at" \
    --command "snyk code test <source-scope/tree> --sarif-file-output=raw.sarif" \
    --tool-version-file "$artifacts/version.txt" --source-scope "$scope_dir/source-scope.json" $config_args
  manifest_status=$?
  if [ "$provenance_binding_failed" -ne 0 ] || [ "$manifest_status" -ne 0 ]; then
    return 1
  fi
  return 0
}
fail_env() {
  printf '%s\n' "$1" >"$artifacts/stderr.log"
  exit_code=1
  status=FAILED_ENV
  finish
  exit 1
}
if [ -z "$benchmark_commit" ] || [ -z "$harness_commit" ]; then
  fail_env "Unable to determine benchmark or harness commit"
fi
if [ "$provenance_init_status" -ne 0 ] || [ ! -s "$provenance" ]; then
  fail_env "Unable to create initial Snyk provenance"
fi
if [ "$consent" != confirmed ]; then
  fail_env "SNYK_WRITTEN_CONSENT=confirmed is required"
fi
case "$snyk_bin" in
  /*) ;;
  *) fail_env "SNYK_BIN must be an absolute executable path" ;;
esac
if [ ! -x "$snyk_bin" ]; then
  fail_env "SNYK_BIN is not executable"
fi
case "$snyk_cache" in
  /*) ;;
  *) fail_env "SNYK_CACHE_PATH must be an absolute writable external directory" ;;
esac
if ! mkdir -p "$snyk_cache" 2>/dev/null; then
  fail_env "SNYK_CACHE_PATH is not writable"
fi
cache_real=$(CDPATH= cd -P -- "$snyk_cache" 2>/dev/null && pwd -P) || fail_env "SNYK_CACHE_PATH is not a directory"
repo_real=$(CDPATH= cd -P -- "$repo_root" && pwd -P)
artifacts_real=$(CDPATH= cd -P -- "$artifacts" && pwd -P)
case "$cache_real" in
  /|"$repo_real"|"$repo_real"/*|"$artifacts_real"|"$artifacts_real"/*) fail_env "SNYK_CACHE_PATH must be outside the repository and artifacts" ;;
esac
if [ ! -w "$cache_real" ]; then
  fail_env "SNYK_CACHE_PATH is not writable"
fi
export SNYK_CACHE_PATH="$cache_real"
binary_sha256=$(shasum -a 256 "$snyk_bin" 2>/dev/null | awk '{print $1}')
if [ "$binary_sha256" != "$expected_sha256" ]; then
  fail_env "SNYK_BIN hash does not match the release-pinned CLI"
fi
version_output=$("$snyk_bin" --version 2>/dev/null)
version_status=$?
version_value=$(printf '%s\n' "$version_output" | awk 'NF {print; exit}')
printf '%s\n' "$version_output" >"$artifacts/version.txt"
if [ "$version_status" -ne 0 ] || [ "$version_value" != "$expected_version" ]; then
  fail_env "SNYK_BIN version does not match the release-pinned CLI"
fi
python3 "$repo_root/tools/snyk_provenance.py" create --output "$provenance" \
  --cli-version "$version_value" --binary-sha256 "$binary_sha256" --authenticated false \
  --consent-confirmed true --cache-isolated true >/dev/null 2>"$artifacts/provenance.stderr.log" || fail_env "Unable to write Snyk provenance"
python3 "$repo_root/tools/source_scope.py" prepare --source "$target" --output "$scope_dir" --source-commit "$benchmark_commit" \
  >"$artifacts/source-scope.stdout.log" 2>"$artifacts/source-scope.stderr.log" || { exit_code=1; finish; exit 1; }
identity_tmp=$(mktemp "${TMPDIR:-/tmp}/snyk-whoami.XXXXXX") || fail_env "Unable to create private Snyk authentication check"
chmod 600 "$identity_tmp"
"$snyk_bin" whoami --json >"$identity_tmp" 2>/dev/null
auth_status=$?
auth_nonempty=0
[ -s "$identity_tmp" ] && auth_nonempty=1
rm -f "$identity_tmp"
identity_tmp=
if [ "$auth_status" -ne 0 ] || [ "$auth_nonempty" -ne 1 ]; then
  if ! python3 "$repo_root/tools/snyk_provenance.py" create --output "$provenance" \
    --cli-version "$version_value" --binary-sha256 "$binary_sha256" --authenticated false \
    --consent-confirmed true --cache-isolated true >/dev/null 2>"$artifacts/provenance.stderr.log"; then
    printf '%s\n' "Unable to write unauthenticated Snyk provenance" >"$artifacts/provenance.stderr.log"
  fi
  fail_env "Snyk whoami authentication check failed"
fi
python3 "$repo_root/tools/snyk_provenance.py" create --output "$provenance" \
  --cli-version "$version_value" --binary-sha256 "$binary_sha256" --authenticated true \
  --consent-confirmed true --cache-isolated true >/dev/null 2>"$artifacts/provenance.stderr.log" || fail_env "Unable to write Snyk provenance"
printf '%s\n' "snyk code test <source-scope/tree> --sarif-file-output=raw.sarif" >"$artifacts/command.txt"
"$snyk_bin" code test "$scope_dir/tree" --sarif-file-output="$artifacts/raw.sarif" \
  >"$artifacts/stdout.log" 2>"$artifacts/stderr.log"
scan_status=$?
exit_code=$scan_status
if [ ! -s "$artifacts/raw.sarif" ] || ! python3 "$repo_root/tools/validate_sarif.py" --input "$artifacts/raw.sarif" \
  >"$artifacts/raw-validation.log" 2>&1; then
  status=INVALID_OUTPUT; finish; exit 1
fi
if ! python3 "$repo_root/tools/snyk_provenance.py" enrich --provenance "$provenance" --sarif "$artifacts/raw.sarif"; then
  status=INVALID_OUTPUT; finish; exit 1
fi
# Snyk documents exit 1 as "findings reported", not a failed scan.
if [ "$scan_status" -ne 0 ] && [ "$scan_status" -ne 1 ]; then status=FAILED_SCAN; finish; exit "$scan_status"; fi
if ! python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json"; then status=INVALID_OUTPUT; finish; exit 1; fi
if ! python3 "$repo_root/tools/score.py" --expected "$target/expectedresults-0.1.csv" --findings "$artifacts/normalized.jsonl" --output "$artifacts/score.json"; then status=INVALID_OUTPUT; finish; exit 1; fi
status=PASS
finish
