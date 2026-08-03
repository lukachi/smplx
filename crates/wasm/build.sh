#!/usr/bin/env bash
# Builds the browser-loadable Simplex SDK module into crates/wasm/pkg.
#
# Output mirrors what lwk_wasm produces and what a wasm-bindgen loader expects:
# smplx_wasm_bg.wasm, smplx_wasm_bg.js, and the .d.ts files beside them.
#
# Usage: crates/wasm/build.sh [bundler|nodejs|web]   (default: bundler)

set -euo pipefail

TARGET_KIND="${1:-bundler}"
CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/../.." && pwd)"
OUT_DIR="${CRATE_DIR}/pkg"

# A wasm-capable C compiler is required. Apple's system clang has no WebAssembly
# backend, and without this the build fails inside secp256k1-sys and simplicity-sys
# with "unable to create target", which points at the crates and misleads.
if [ -z "${CC_wasm32_unknown_unknown:-}" ]; then
	for candidate in /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang /usr/bin/clang; do
		if [ -x "${candidate}" ] && "${candidate}" -print-targets 2>/dev/null | grep -q wasm32; then
			export CC_wasm32_unknown_unknown="${candidate}"
			export AR_wasm32_unknown_unknown="$(dirname "${candidate}")/llvm-ar"
			break
		fi
	done
fi

if [ -z "${CC_wasm32_unknown_unknown:-}" ]; then
	echo "error: no C compiler with a WebAssembly backend was found." >&2
	echo "       Install LLVM (brew install llvm) and set CC_wasm32_unknown_unknown" >&2
	echo "       and AR_wasm32_unknown_unknown to its clang and llvm-ar." >&2
	exit 1
fi

# wasm-bindgen refuses to run when the CLI and the crate disagree on the bindgen
# schema. The crate is pinned exactly in Cargo.toml; check the CLI matches before
# spending a full release build on it.
CRATE_VERSION="$(grep -oE '"=?[0-9]+\.[0-9]+\.[0-9]+"' "${CRATE_DIR}/Cargo.toml" | tr -d '"=' | tail -1)"
CLI_VERSION="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"

if [ "${CRATE_VERSION}" != "${CLI_VERSION}" ]; then
	echo "error: wasm-bindgen CLI is ${CLI_VERSION}, the crate is pinned to ${CRATE_VERSION}." >&2
	echo "       Run: cargo install wasm-bindgen-cli --version ${CRATE_VERSION}" >&2
	exit 1
fi

cd "${WORKSPACE_DIR}"

cargo build -p smplx-wasm --release --target wasm32-unknown-unknown

wasm-bindgen \
	--target "${TARGET_KIND}" \
	--out-dir "${OUT_DIR}" \
	"target/wasm32-unknown-unknown/release/smplx_wasm.wasm"

echo
echo "Built ${OUT_DIR} (${TARGET_KIND}):"
ls -l "${OUT_DIR}"
