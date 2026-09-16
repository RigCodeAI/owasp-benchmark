#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 BENCHMARK_DIR TARGET_BASE_URL ARTIFACT_DIR" >&2
  echo "ZAP_PROXY must point at an already-running ZAP proxy, for example http://127.0.0.1:8080" >&2
  exit 2
fi
benchmark=$(CDPATH= cd -- "$1" && pwd)
base_url=$2
mkdir -p "$3"
artifacts=$(CDPATH= cd -- "$3" && pwd)
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
proxy=${ZAP_PROXY:?set ZAP_PROXY to the running ZAP proxy URL}

printf '%s\n' "traffic.py replay --proxy ZAP_PROXY --base-url TARGET_BASE_URL" >"$artifacts/command.txt"
python3 "$repo_root/tools/traffic.py" replay \
  --crawler "$benchmark/data/benchmark-crawler-http.xml" \
  --base-url "$base_url" --proxy "$proxy" --insecure \
  --coverage-output "$artifacts/coverage.json"

cat <<EOF
Seed traffic is recorded in ZAP and coverage.json is ready.
Next, import $benchmark/data/openapi.yaml in ZAP, run an active scan of $base_url,
and export SARIF to $artifacts/raw.sarif. Then run:

python3 $repo_root/tools/normalize_sarif.py --input $artifacts/raw.sarif --output $artifacts/normalized.jsonl --diagnostics $artifacts/normalization.json
python3 $repo_root/tools/score.py --expected $benchmark/expectedresults-0.1.csv --findings $artifacts/normalized.jsonl --coverage $artifacts/coverage.json --output $artifacts/score.json
EOF
