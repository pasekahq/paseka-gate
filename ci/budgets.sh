#!/usr/bin/env bash
# Budgets of the static release binary and its dependency tree.
#   size: PASEKA_MAX_BINARY_BYTES (default 6 MiB), static linking required;
#   dependencies: PASEKA_MAX_DEPS distinct external crates in the normal build graph of the
#   binary for the musl target (default 80).
# Idle RSS and idle wakeups join here once `paseka serve` exists.
# Usage: ci/budgets.sh [path/to/paseka]   (default: target/x86_64-unknown-linux-musl/release/paseka)
set -euo pipefail

target_dir="${CARGO_TARGET_DIR:-target}"
bin="${1:-$target_dir/x86_64-unknown-linux-musl/release/paseka}"
max_bytes="${PASEKA_MAX_BINARY_BYTES:-6291456}"
max_deps="${PASEKA_MAX_DEPS:-80}"
fail=0

size=$(stat -c %s "$bin")
echo "binary: $bin $size bytes (budget $max_bytes)"
if [ "$size" -gt "$max_bytes" ]; then
  echo "::error::binary size $size > budget $max_bytes"; fail=1
fi
if file "$bin" | grep -q 'dynamically linked'; then
  echo "::error::binary is dynamically linked, expected static"; fail=1
fi

deps=$(cargo tree --locked -e normal -p paseka --prefix none --target x86_64-unknown-linux-musl \
  | sed 's/ (\*)$//' | sort -u | grep -cv '^paseka')
echo "dependencies: $deps external crates (budget $max_deps)"
if [ "$deps" -gt "$max_deps" ]; then
  echo "::error::dependency count $deps > budget $max_deps"; fail=1
fi
exit "$fail"
