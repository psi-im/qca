#!/usr/bin/env bash
set -euo pipefail

src=$1
prefix=$2
host=${3:-}

mkdir -p "$prefix"

configure_args=(
    "--prefix=$prefix"
    --enable-static
    --with-threads=pthread
    --disable-shared
    --enable-plain
    --enable-scram
    --enable-digest
    --disable-anon
    --disable-cram
    --disable-login
    --disable-ntlm
    --disable-otp
    --disable-srp
    --disable-sample
    --disable-sql
    --disable-gssapi
    --disable-gs2
    --with-dblib=none
    --with-saslauthd=no
    --with-authdaemond=no
    --with-pwcheck=no
    --without-pam
    --without-ldap
)
if [[ -n "$host" ]]; then
    configure_args+=("--host=$host")
fi

pushd "$src"
CFLAGS="${CFLAGS:-} -fPIC" ./configure "${configure_args[@]}"
make -j"${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
make install
popd

# Keep the dependency bundle intentionally small and deterministic.
rm -rf "$prefix/bin" "$prefix/sbin" "$prefix/share" "$prefix/lib/sasl2" 2>/dev/null || true
find "$prefix/lib" -type f \( -name '*.la' -o -name '*.dylib' -o -name '*.so*' \) -delete 2>/dev/null || true
