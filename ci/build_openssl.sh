#!/bin/sh
set -eu

OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.0}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$PWD/.openssl/$OPENSSL_VERSION}"

if [ -x "$OPENSSL_PREFIX/bin/openssl" ]; then
    exit 0
fi

BUILD_ROOT="$(mktemp -d)"
ARCHIVE="$BUILD_ROOT/openssl-$OPENSSL_VERSION.tar.gz"
SOURCE_DIR="$BUILD_ROOT/openssl-$OPENSSL_VERSION"

cleanup() {
    rm -rf "$BUILD_ROOT"
}
trap cleanup EXIT

curl -fsSL \
    -o "$ARCHIVE" \
    "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
tar -xzf "$ARCHIVE" -C "$BUILD_ROOT"

cd "$SOURCE_DIR"
./config --prefix="$OPENSSL_PREFIX" --openssldir="$OPENSSL_PREFIX/ssl"
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
make install_sw
