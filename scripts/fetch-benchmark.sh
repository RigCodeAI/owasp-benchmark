#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination=${BENCHMARK_DIR:-"$repo_root/benchmark"}
repository=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["repository"])' "$repo_root/benchmark.lock.json")
commit=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' "$repo_root/benchmark.lock.json")

if [ -e "$destination" ]; then
  if [ ! -d "$destination/.git" ]; then
    echo "Refusing to replace non-git path: $destination" >&2
    exit 1
  fi
  if [ -n "$(git -C "$destination" status --porcelain)" ]; then
    echo "Refusing to modify a dirty benchmark checkout: $destination" >&2
    exit 1
  fi
else
  git clone --filter=blob:none --no-checkout "$repository" "$destination"
fi

git -C "$destination" fetch --depth=1 origin "$commit"
git -C "$destination" checkout --detach "$commit"
python3 "$repo_root/tools/verify_lock.py" --benchmark "$destination"
