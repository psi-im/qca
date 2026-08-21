#!/usr/bin/env bash
set -euo pipefail

src=$1
prefix=$2
host=${3:-}

mkdir -p "$prefix"

configure_args=(
  "--prefix=$prefix"
  --enable-static
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
# Cyrus SASL 2.1.28 is not reliably parallel-build safe. This dependency is
# built once per immutable bundle revision, so prefer correctness here.
make

archive=lib/.libs/libsasl2.a
if [[ ! -f "$archive" ]]; then
  echo "Static Cyrus SASL archive was not produced: $archive" >&2
  exit 1
fi

# Fail here rather than later in QCA if the static plug-in registry references
# mechanisms that were not actually embedded in libsasl2.a.
nm_bin=${NM:-nm}
for symbol in \
  plain_client_plug_init plain_server_plug_init \
  scram_client_plug_init scram_server_plug_init \
  digestmd5_client_plug_init digestmd5_server_plug_init; do
  if ! "$nm_bin" -g "$archive" 2>/dev/null | awk -v wanted="$symbol" '
    {
      if (NF < 2)
        next
      name = $NF
      type = $(NF - 1)
      sub(/^_/, "", name)
      if (name == wanted && type == "T")
        found = 1
    }
    END { exit found ? 0 : 1 }
  '; then
    echo "Static Cyrus SASL archive is missing definition of $symbol" >&2
    exit 1
  fi
done

make install
popd

# Keep the dependency bundle intentionally small and deterministic.
rm -rf "$prefix/bin" "$prefix/sbin" "$prefix/share" "$prefix/lib/sasl2" 2>/dev/null || true
find "$prefix/lib" -type f \( -name '*.la' -o -name '*.dylib' -o -name '*.so*' \) -delete 2>/dev/null || true
