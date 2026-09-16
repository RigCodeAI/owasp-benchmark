#!/bin/sh
set -eu

# Phase 0 only: image/version, Automation Framework plan, private topology,
# health, and writable-state checks. This script never starts a scan.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
benchmark=${BENCHMARK_DIR:-"$repo_root/benchmark"}
artifact_dir=${ZAP_ARTIFACT_DIR:-"$(mktemp -d "${TMPDIR:-/tmp}/phase0-zap.XXXXXX")"}
project=${ZAP_COMPOSE_PROJECT:-phase0-zap-smoke}
compose_file=${ZAP_COMPOSE_FILE:-"$repo_root/configs/zap-compose.example.yml"}
zap_image=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0}
zap_digest=${ZAP_IMAGE_DIGEST:-sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef}
benchmark_image=${BENCHMARK_IMAGE:-owasp-benchmarkpython:phase0}
compose="docker compose -p $project -f $compose_file"

cleanup() {
  $compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

[ -d "$benchmark/.git" ] || { echo "pinned benchmark checkout is required: $benchmark" >&2; exit 1; }
mkdir -p "$artifact_dir"
chmod 0700 "$artifact_dir"
docker pull "$zap_image@$zap_digest" >/dev/null
docker run --rm --platform linux/arm64 --read-only --tmpfs /tmp:size=128m --tmpfs /home/zap/.ZAP:size=512m,uid=1000,gid=1000,mode=700 --tmpfs /home/zap/.java:size=16m,uid=1000,gid=1000,mode=700 \
  "$zap_image@$zap_digest" zap.sh -version
docker build --platform linux/arm64 -f "$repo_root/configs/benchmark.Dockerfile" -t "$benchmark_image" "$benchmark"

export BENCHMARK_IMAGE="$benchmark_image"
export ZAP_COMPOSE_PROJECT="$project" ZAP_COMPOSE_FILE="$compose_file"
export ZAP_IMAGE="$zap_image" ZAP_IMAGE_DIGEST="$zap_digest"
export TRAFFIC_TOOL_PATH="$repo_root/tools/traffic.py"
export CRAWLER_XML_PATH="$benchmark/data/benchmark-crawler-http.xml"
export ZAP_PLAN_PATH="$repo_root/configs/zap-automation.example.yaml"
export ZAP_ARTIFACT_DIR="$artifact_dir"

"$repo_root/scripts/zap-topology.sh" prepare
$compose run --rm --no-deps zap zap.sh -version
$compose run --rm --no-deps zap zap.sh -cmd -autocheck /zap/wrk/zap-plan.yaml
"$repo_root/scripts/zap-topology.sh" up
$compose exec -T benchmark python -c 'import urllib.request; response=urllib.request.urlopen("http://127.0.0.1:8000/benchmark/Index.html", timeout=5); assert response.status == 200'
$compose exec -T zap sh -c 'printf phase0-write-smoke > /zap/wrk/artifacts/.phase0-write-smoke && test "$(cat /zap/wrk/artifacts/.phase0-write-smoke)" = phase0-write-smoke'
"$repo_root/scripts/zap-export-artifacts.sh" "$compose_file" "$project" "$artifact_dir" 1
test "$(cat "$artifact_dir/.phase0-write-smoke")" = phase0-write-smoke
rm -f "$artifact_dir/.phase0-write-smoke"
echo "Phase 0 ZAP integration checks passed"
