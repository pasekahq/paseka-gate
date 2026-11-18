#!/usr/bin/env bash
# Reproducible release build of the static binary; prints its sha256.
# Two runs from the same commit with the toolchain pinned in rust-toolchain.toml MUST print the
# same digest, on any host and in any checkout path.
# Usage: ci/repro-build.sh [out-dir]   (default: dist)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
out="${1:-dist}"
target=x86_64-unknown-linux-musl
toolchain="${RUSTUP_TOOLCHAIN:-$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)}"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export PASEKA_BUILD_COMMIT="${PASEKA_BUILD_COMMIT:-$(git rev-parse HEAD)}"
export CARGO_INCREMENTAL=0
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"
# A fixed target dir and remapped paths keep the checkout path, home and registry out of the binary.
export CARGO_TARGET_DIR="${PASEKA_REPRO_TARGET_DIR:-$root/target/repro}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$root=/build --remap-path-prefix=$cargo_home=/cargo -C codegen-units=1 -C strip=symbols"

cargo "+$toolchain" build --release --locked --target "$target" -p paseka
mkdir -p "$out"
cp "$CARGO_TARGET_DIR/$target/release/paseka" "$out/paseka-$target"
touch -d "@$SOURCE_DATE_EPOCH" "$out/paseka-$target"
(cd "$out" && sha256sum "paseka-$target" | tee "paseka-$target.sha256")
