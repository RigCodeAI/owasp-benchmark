#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 BENCHMARK_DIR ARTIFACT_DIR" >&2
  exit 2
fi
target=$(CDPATH= cd -- "$1" && pwd)
mkdir -p "$2"
artifacts=$(CDPATH= cd -- "$2" && pwd)
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
rules=${SEMGREP_RULES:-p/python}

semgrep --version >"$artifacts/version.txt"
printf '%s\n' "semgrep scan --config $rules --sarif --output raw.sarif TARGET" >"$artifacts/command.txt"
semgrep scan --config "$rules" --sarif --output "$artifacts/raw.sarif" "$target" \
  >"$artifacts/stdout.log" 2>"$artifacts/stderr.log"
python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" \
  --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json"
python3 "$repo_root/tools/score.py" \
  --expected "$target/expectedresults-0.1.csv" --findings "$artifacts/normalized.jsonl" \
  --output "$artifacts/score.json"
