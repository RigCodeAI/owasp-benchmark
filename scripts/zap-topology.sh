#!/bin/sh
set -u

# Lifecycle wrapper for the private BenchmarkPython/ZAP network. `prepare`
# removes and recreates scoped volumes, then initializes their ownership before
# any ZAP preflight command. Call `prepare` followed by `up` for a fresh run;
# `up` deliberately preserves the prepared named volumes. `down` removes them.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file=${ZAP_COMPOSE_FILE:-"$repo_root/configs/zap-compose.example.yml"}
project=${ZAP_COMPOSE_PROJECT:-owasp-benchmark-zap}

if [ "$#" -ne 1 ] || { [ "$1" != prepare ] && [ "$1" != up ] && [ "$1" != down ]; }; then
  echo "usage: $0 prepare|up|down" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the private topology" >&2
  exit 1
fi

require_runtime_inputs() {
  : "${BENCHMARK_IMAGE:?set BENCHMARK_IMAGE for the pinned BenchmarkPython image}"
  : "${ZAP_IMAGE_DIGEST:?set immutable ZAP_IMAGE_DIGEST}"
  : "${ZAP_PLATFORM_DIGEST:?set immutable arm64 ZAP_PLATFORM_DIGEST}"
  : "${TRAFFIC_TOOL_PATH:?set exact traffic.py path}"
  : "${CRAWLER_XML_PATH:?set exact crawler XML path}"
  : "${ZAP_PLAN_PATH:?set exact Automation plan path}"
  : "${ZAP_ARTIFACT_DIR:?set private artifact dir}"
  mkdir -p "$ZAP_ARTIFACT_DIR"
  chmod 0700 "$ZAP_ARTIFACT_DIR"
  if [ ! -d "$ZAP_ARTIFACT_DIR" ] || [ ! -w "$ZAP_ARTIFACT_DIR" ]; then
    echo "ZAP_ARTIFACT_DIR must be a writable private host directory" >&2
    exit 1
  fi
}

if [ "$1" = prepare ]; then
  require_runtime_inputs
  # This is the only destructive operation and is constrained to this
  # explicitly selected Compose project and file.
  docker compose -p "$project" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1
  # The init container is root only for CHOWN. Persistent services stay UID
  # 1000, read-only, and cap_drop=ALL in the Compose topology.
  docker compose -p "$project" -f "$compose_file" run --rm --no-deps --user 0:0 --entrypoint /bin/sh \
    --cap-drop ALL --cap-add CHOWN zap -c \
    'chown -R 1000:1000 /zap/wrk/artifacts /home/zap/.ZAP /home/zap/.java'
  exit $?
fi

if [ "$1" = up ]; then
  require_runtime_inputs
  exec docker compose -p "$project" -f "$compose_file" up -d --force-recreate --renew-anon-volumes
fi

exec docker compose -p "$project" -f "$compose_file" down --volumes --remove-orphans
