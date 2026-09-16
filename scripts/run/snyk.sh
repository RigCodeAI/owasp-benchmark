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

snyk --version >"$artifacts/version.txt" || exit $?
printf '%s\n' "snyk code test TARGET --sarif-file-output=raw.sarif" >"$artifacts/command.txt"
snyk code test "$target" --sarif-file-output="$artifacts/raw.sarif" \
  >"$artifacts/stdout.log" 2>"$artifacts/stderr.log"
status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
  echo "Snyk failed with exit code $status" >&2
  exit "$status"
fi
python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" \
  --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json" || exit $?
python3 "$repo_root/tools/score.py" \
  --expected "$target/expectedresults-0.1.csv" --findings "$artifacts/normalized.jsonl" \
  --output "$artifacts/score.json"
