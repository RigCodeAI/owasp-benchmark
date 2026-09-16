#!/bin/sh
set -eu

echo "Rig runner is intentionally disabled until the public CLI contract is ready." >&2
echo "It must reuse tools/traffic.py and emit SARIF or common-schema JSONL plus coverage.json." >&2
exit 2
