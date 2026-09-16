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
database="$artifacts/codeql-db"
suite=${CODEQL_SUITE:-codeql/python-queries:codeql-suites/python-security-extended.qls}

if [ -e "$database" ]; then
  echo "Refusing to replace existing CodeQL database: $database" >&2
  exit 1
fi
codeql version --format=json >"$artifacts/version.json"
printf '%s\n' "codeql database create codeql-db --language=python --source-root=TARGET --build-mode=none" \
  "codeql database analyze codeql-db $suite --format=sarifv2.1.0 --output=raw.sarif" >"$artifacts/command.txt"
codeql database create "$database" --language=python --source-root="$target" --build-mode=none \
  >"$artifacts/create.stdout.log" 2>"$artifacts/create.stderr.log"
codeql database analyze "$database" "$suite" --format=sarifv2.1.0 --output="$artifacts/raw.sarif" \
  >"$artifacts/stdout.log" 2>"$artifacts/stderr.log"
python3 "$repo_root/tools/normalize_sarif.py" --input "$artifacts/raw.sarif" \
  --output "$artifacts/normalized.jsonl" --diagnostics "$artifacts/normalization.json"
python3 "$repo_root/tools/score.py" \
  --expected "$target/expectedresults-0.1.csv" --findings "$artifacts/normalized.jsonl" \
  --output "$artifacts/score.json"
