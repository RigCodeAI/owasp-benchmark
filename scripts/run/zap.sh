#!/bin/sh
set -u

if [ "$#" -ne 3 ]; then
  echo "usage: $0 BENCHMARK_DIR http://benchmark:8000 ARTIFACT_DIR" >&2
  exit 2
fi
benchmark=$(CDPATH= cd -- "$1" && pwd)
base_url=$2
mkdir -p "$3"
artifacts=$(CDPATH= cd -- "$3" && pwd)
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
plan=${ZAP_AUTOMATION_PLAN:-"$repo_root/configs/zap-automation.example.yaml"}
compose_file=${ZAP_COMPOSE_FILE:-"$repo_root/configs/zap-compose.example.yml"}
project=${ZAP_COMPOSE_PROJECT:-owasp-benchmark-zap}
image=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0}
image_digest=${ZAP_IMAGE_DIGEST:-sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef}
platform_digest=${ZAP_PLATFORM_DIGEST:-sha256:05cbf4cab5d2fdaef55b0cd0b586f22d0ce4f75e0995f3cea2db23afbbdfd2f8}
run_id=${RUN_ID:-$(basename "$artifacts")}
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
benchmark_commit=$(git -C "$benchmark" rev-parse HEAD 2>/dev/null || true)
harness_commit=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)
status=FAILED_ENV
exit_code=127
compose="docker compose -p $project -f $compose_file"
plan_artifact_name=automation-plan.yaml
topology_started=0
printf '%s\n' "traffic.py replay through private compose network" "ZAP daemon API active scan/report export using pinned plan" >"$artifacts/command.txt"
printf '%s\n' "unavailable" >"$artifacts/zap-runtime.json"
cleanup() { command -v docker >/dev/null 2>&1 && $compose down --volumes --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
export_artifacts() {
  "$repo_root/scripts/zap-export-artifacts.sh" "$compose_file" "$project" "$artifacts" "$topology_started" \
    >"$artifacts/artifact-export.stdout.log" 2>"$artifacts/artifact-export.stderr.log"
}
finish() {
  if ! export_artifacts; then
    status=FAILED_ENV
    [ "$exit_code" -eq 0 ] && exit_code=1
  fi
  plan_sha256=
  config_args=
  if [ -f "$plan" ]; then
    plan_sha256=$(shasum -a 256 "$plan" | awk '{print $1}')
    if [ ! -f "$artifacts/$plan_artifact_name" ]; then
      cp "$plan" "$artifacts/$plan_artifact_name"
    fi
    config_args="--config-path $plan_artifact_name --config-sha256 $plan_sha256"
  fi
  coverage_args=
  [ -f "$artifacts/coverage.json" ] && coverage_args="--coverage-reference coverage.json"
  python3 "$repo_root/tools/run_manifest.py" create --artifact-dir "$artifacts" --run-id "$run_id" \
    --tool owasp-zap --method dast --benchmark-commit "${benchmark_commit:-0000000000000000000000000000000000000000}" \
    --harness-commit "${harness_commit:-0000000000000000000000000000000000000000}" \
    --status "$status" --exit-code "$exit_code" --started-at "$started_at" \
    --command "traffic.py replay --proxy <private-zap-proxy> --base-url http://benchmark:8000" \
    --command "ZAP daemon API active scan/report export --plan <pinned-plan>" \
    --tool-version-file "$artifacts/zap-runtime.json" $config_args \
    $coverage_args
}
if [ "$base_url" != "http://benchmark:8000" ] && [ "$base_url" != "http://benchmark:8000/" ]; then
  printf '%s\n' "target must be the single private URL http://benchmark:8000" >"$artifacts/stderr.log"; finish; exit 1
fi
if [ "$image" != "ghcr.io/zaproxy/zaproxy:2.17.0" ]; then
  printf '%s\n' "ZAP_IMAGE must be the release-pinned ghcr.io/zaproxy/zaproxy:2.17.0" >"$artifacts/stderr.log"; finish; exit 1
fi
if [ "$platform_digest" != "sha256:05cbf4cab5d2fdaef55b0cd0b586f22d0ce4f75e0995f3cea2db23afbbdfd2f8" ]; then
  printf '%s\n' "ZAP_PLATFORM_DIGEST does not match the release-pinned arm64 child" >"$artifacts/stderr.log"; finish; exit 1
fi
if [ -z "$benchmark_commit" ] || [ -z "$harness_commit" ] || ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' "benchmark/harness commit and Docker are required" >"$artifacts/stderr.log"; finish; exit 1
fi
if ! python3 "$repo_root/tools/zap_automation.py" validate-plan --plan "$plan" --target-url "http://benchmark:8000/benchmark" --image-digest "$image_digest" \
  >"$artifacts/plan-validation.stdout.log" 2>"$artifacts/plan-validation.stderr.log"; then finish; exit 1; fi
if ! python3 "$repo_root/tools/zap_automation.py" validate-alert-canary --canary "$repo_root/configs/zap-alert-mapping-canary.json" \
  >"$artifacts/alert-canary-validation.stdout.log" 2>"$artifacts/alert-canary-validation.stderr.log"; then finish; exit 1; fi
export TRAFFIC_TOOL_PATH="$repo_root/tools/traffic.py"
export CRAWLER_XML_PATH="$benchmark/data/benchmark-crawler-http.xml"
export ZAP_PLAN_PATH="$plan"
export ZAP_ARTIFACT_DIR="$artifacts"
export BENCHMARK_IMAGE=${BENCHMARK_IMAGE:?set image built from benchmark.lock.json}
export ZAP_IMAGE="$image" ZAP_IMAGE_DIGEST="$image_digest" ZAP_PLATFORM_DIGEST="$platform_digest"
if ! "$repo_root/scripts/zap-topology.sh" prepare >"$artifacts/topology-prepare.stdout.log" 2>"$artifacts/topology-prepare.stderr.log"; then finish; exit 1; fi
if ! $compose run --rm --no-deps zap zap.sh -cmd -autocheck /zap/wrk/zap-plan.yaml >"$artifacts/plan-image-validation.stdout.log" 2>"$artifacts/plan-image-validation.stderr.log"; then finish; exit 1; fi
if ! "$repo_root/scripts/zap-topology.sh" up >"$artifacts/topology.stdout.log" 2>"$artifacts/topology.stderr.log"; then finish; exit 1; fi
topology_started=1
$compose exec -T zap python /opt/harness/traffic.py manifest --crawler /opt/harness/benchmark-crawler-http.xml --output /zap/wrk/artifacts/traffic-manifest.json >"$artifacts/traffic-manifest.stdout.log" 2>"$artifacts/traffic-manifest.stderr.log" || { exit_code=1; finish; exit 1; }
$compose exec -T zap python /opt/harness/traffic.py replay --crawler /opt/harness/benchmark-crawler-http.xml --base-url http://benchmark:8000 --proxy http://127.0.0.1:8080 --insecure --allow-remote --coverage-output /zap/wrk/artifacts/coverage.json >"$artifacts/seed.stdout.log" 2>"$artifacts/seed.stderr.log"
seed_status=$?
if [ "$seed_status" -ne 0 ]; then exit_code=$seed_status; status=INCOMPLETE_COVERAGE; finish; exit 1; fi
if ! export_artifacts; then exit_code=1; status=FAILED_ENV; finish; exit 1; fi
python3 "$repo_root/tools/zap_automation.py" validate-coverage --coverage "$artifacts/coverage.json" --planned 1230 >"$artifacts/coverage-validation.stdout.log" 2>"$artifacts/coverage-validation.stderr.log" || { status=INCOMPLETE_COVERAGE; finish; exit 1; }
$compose exec -T zap python /opt/harness/traffic.py zap-history --base http://127.0.0.1:8080 --coverage /zap/wrk/artifacts/coverage.json --output /zap/wrk/artifacts/zap-history.json >"$artifacts/history.stdout.log" 2>"$artifacts/history.stderr.log" || { status=INCOMPLETE_COVERAGE; finish; exit 1; }
if ! export_artifacts; then exit_code=1; status=FAILED_ENV; finish; exit 1; fi
python3 "$repo_root/tools/zap_automation.py" validate-history --history "$artifacts/zap-history.json" --coverage "$artifacts/coverage.json" --planned 1230 >"$artifacts/history-validation.stdout.log" 2>"$artifacts/history-validation.stderr.log" || { status=INCOMPLETE_COVERAGE; finish; exit 1; }
if ! python3 "$repo_root/tools/zap_automation.py" make-boundary --history "$artifacts/zap-history.json" --output "$artifacts/seed-boundary.json"; then
  exit_code=1; status=INCOMPLETE_COVERAGE; finish; exit 1
fi
$compose exec -T zap python /opt/harness/traffic.py zap-passive --base http://127.0.0.1:8080 --output /zap/wrk/artifacts/passive-scan.json --timeout 900 >"$artifacts/passive.stdout.log" 2>"$artifacts/passive.stderr.log" || { status=INCOMPLETE_COVERAGE; finish; exit 1; }
if ! export_artifacts; then exit_code=1; status=FAILED_ENV; finish; exit 1; fi
$compose exec -T zap python /opt/harness/traffic.py zap-active --base http://127.0.0.1:8080 --target http://benchmark:8000/benchmark --output /zap/wrk/artifacts/active-scan.json --timeout 1800 >"$artifacts/active.stdout.log" 2>"$artifacts/active.stderr.log" || { status=INCOMPLETE_COVERAGE; finish; exit 1; }
if ! export_artifacts; then exit_code=1; status=FAILED_ENV; finish; exit 1; fi
$compose exec -T zap python /opt/harness/traffic.py zap-reports --base http://127.0.0.1:8080 --target http://benchmark:8000/benchmark --output-dir /zap/wrk/artifacts >"$artifacts/reports.stdout.log" 2>"$artifacts/reports.stderr.log" || { status=INVALID_OUTPUT; finish; exit 1; }
$compose exec -T zap python /opt/harness/traffic.py zap-metadata --base http://127.0.0.1:8080 --output-dir /zap/wrk/artifacts --image "$image" --digest "$image_digest" --platform-digest "$platform_digest" --plan /zap/wrk/zap-plan.yaml --project "$project" --target http://benchmark:8000/benchmark >"$artifacts/metadata.stdout.log" 2>"$artifacts/metadata.stderr.log" || { status=FAILED_ENV; finish; exit 1; }
if ! export_artifacts; then exit_code=1; status=FAILED_ENV; finish; exit 1; fi
if [ ! -s "$artifacts/zap-report.json" ] || [ ! -s "$artifacts/raw.sarif" ]; then status=INVALID_OUTPUT; finish; exit 1; fi
python3 "$repo_root/tools/validate_sarif.py" --input "$artifacts/raw.sarif" >"$artifacts/raw-validation.log" 2>&1 || { status=INVALID_OUTPUT; finish; exit 1; }
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$artifacts/zap-report.json" || { status=INVALID_OUTPUT; finish; exit 1; }
python3 -c 'import json,sys; raise SystemExit(0 if json.load(open(sys.argv[1])).get("completed") is True else 1)' "$artifacts/active-scan.json" || { status=INCOMPLETE_COVERAGE; finish; exit 1; }
python3 -c 'import json,sys; raise SystemExit(0 if json.load(open(sys.argv[1])).get("completed") is True else 1)' "$artifacts/passive-scan.json" || { status=INCOMPLETE_COVERAGE; finish; exit 1; }
python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json" || { status=INVALID_OUTPUT; finish; exit 1; }
python3 "$repo_root/tools/score.py" --expected "$benchmark/expectedresults-0.1.csv" --findings "$artifacts/normalized.jsonl" --coverage "$artifacts/coverage.json" --output "$artifacts/score.json" || { status=INVALID_OUTPUT; finish; exit 1; }
status=PASS
exit_code=0
finish
