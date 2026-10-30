#!/usr/bin/env bash
# Incremental cargo build/test with the environment `foundation sim` sets, for use inside
# `foundation develop` after one `foundation sim` has staged target/foundation. Examples:
#   tools/host-build.sh build
#   tools/host-build.sh test --workspace
#   RUSTFLAGS="--cfg keyos -C relocation-model=pic -C link-arg=-pie -Zunstable-options" \
#     tools/host-build.sh build --target armv7a-unknown-xous-elf   # device target, unsigned
set -euo pipefail
cd "$(dirname "$0")/.."
export FOUNDATION_UI_LIBRARY_PATH=$PWD/target/foundation/ui/ui
export FOUNDATION_THEMES_SLINT_DIR=$PWD/target/foundation/themes/slint
export FOUNDATION_THEMES_RUST_DIR=$PWD/target/foundation/themes/rust
exec cargo "$@"
