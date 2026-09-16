#!/bin/sh
set -u

# Export the named zap_artifacts volume to the private host artifact directory.
# The optional fourth argument requires an existing ZAP container; early
# preflight failures may call this helper before the topology exists.
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 COMPOSE_FILE COMPOSE_PROJECT ARTIFACT_DIR [require-container]" >&2
  exit 2
fi
compose_file=$1
project=$2
artifacts=$3
require_container=${4:-0}

if ! command -v docker >/dev/null 2>&1; then
  [ "$require_container" = "1" ] && {
    echo "docker is required to export ZAP artifacts" >&2
    exit 1
  }
  exit 0
fi
mkdir -p "$artifacts"
chmod 0700 "$artifacts"
compose="docker compose -p $project -f $compose_file"
container_id=$($compose ps -q zap 2>/dev/null || true)
if [ -z "$container_id" ]; then
  if [ "$require_container" = "1" ]; then
    echo "ZAP container is unavailable while artifact export is required" >&2
    exit 1
  fi
  exit 0
fi
if ! $compose cp zap:/zap/wrk/artifacts/. "$artifacts/"; then
  echo "failed to export /zap/wrk/artifacts from the named zap_artifacts volume" >&2
  exit 1
fi
