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
  --disable-cmulocal
  --disable-krb4
  --disable-macos-framework
  --with-dblib=none
  --with-sphinx-build=no
  --with-saslauthd=no
  --with-authdaemond=no
  --with-pwcheck=no
  --without-pam
  --without-ldap
)
if [[ -n "$host" ]]; then
  configure_args+=("--host=$host")
  # Gentoo explicitly separates the build-machine compiler from the target
  # compiler for cross builds. This is important for configure-time helpers.
  export CC_FOR_BUILD="${CC_FOR_BUILD:-cc}"
fi

pushd "$src"
# Gentoo pins C17 because Cyrus SASL 2.1.28 does not build cleanly as C23.
# PIC is required because this archive is linked into a QCA shared/module plugin.
CFLAGS="${CFLAGS:-} -std=gnu17 -fPIC" ./configure "${configure_args[@]}"
make -j"${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
make install
popd

# Keep the dependency bundle intentionally small and deterministic.
rm -rf "$prefix/bin" "$prefix/sbin" "$prefix/share" "$prefix/lib/sasl2" 2>/dev/null || true
find "$prefix/lib" -type f \( -name '*.la' -o -name '*.dylib' -o -name '*.so*' \) -delete 2>/dev/null || true
