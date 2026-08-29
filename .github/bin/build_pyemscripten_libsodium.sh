#!/bin/bash
#
# Cross-compile the bundled libsodium for wasm32-emscripten.
#
# Required env vars:
#   SODIUM_SRC   - absolute path to the bundled libsodium source tree
#   SODIUM_PATH  - absolute install prefix
#
# Optional env vars (mirror setup.py's build_clib contract):
#   LIBSODIUM_MAKE_ARGS     - args to `make` (default: -j$(nproc))
#   SODIUM_INSTALL_MINIMAL  - if non-empty, pass --enable-minimal
#
# Requires emsdk activated on PATH (emcc, emconfigure, emmake).
# Idempotent so a warm actions/cache hit short-circuits the rebuild.

set -euo pipefail

: "${SODIUM_SRC:?SODIUM_SRC must point at the bundled libsodium source tree}"
: "${SODIUM_PATH:?SODIUM_PATH must point at the install prefix}"

if [ -f "${SODIUM_PATH}/lib/libsodium.a" ]; then
    echo "libsodium already built at ${SODIUM_PATH}; skipping rebuild."
    exit 0
fi

# A fresh checkout on case-insensitive or unusual filesystems can lose +x.
chmod +x "${SODIUM_SRC}/configure" "${SODIUM_SRC}/autogen.sh" 2>/dev/null || true

mkdir -p "${SODIUM_PATH}"

NCORES="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
read -r -a MAKE_ARGS <<< "${LIBSODIUM_MAKE_ARGS:--j${NCORES}}"

CONFIGURE_EXTRA=()
if [ -n "${SODIUM_INSTALL_MINIMAL:-}" ]; then
    CONFIGURE_EXTRA+=(--enable-minimal)
fi

pushd "${SODIUM_SRC}"

# The first six flags below also appear in setup.py:131-149 — keep both
# sites in sync. The remainder are emscripten-specific and would be
# rejected (or wrong) on a native build.
emconfigure ./configure \
    --host=wasm32-unknown-emscripten \
    --disable-shared \
    --enable-static \
    --with-pic \
    --disable-asm \
    --disable-pie \
    --disable-ssp \
    --disable-dependency-tracking \
    --disable-debug \
    --without-pthreads \
    "${CONFIGURE_EXTRA[@]}" \
    --prefix="${SODIUM_PATH}"

emmake make "${MAKE_ARGS[@]}"
emmake make install

popd

test -f "${SODIUM_PATH}/lib/libsodium.a"
test -f "${SODIUM_PATH}/include/sodium.h"
echo "libsodium cross-compiled successfully to ${SODIUM_PATH}"
