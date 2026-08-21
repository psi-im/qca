#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: prepare-cyrus-source.sh VERSION [--autoreconf]}
mode=${2:-}
source_dir="cyrus-sasl-${version}"
source_archive="${source_dir}.tar.gz"
patchset=${CYRUS_GENTOO_PATCHSET:-"cyrus-sasl-${version}-r4-patches"}
patch_archive="${patchset}.tar.xz"
patch_dir="gentoo-cyrus-patches"

# From Gentoo dev-libs/cyrus-sasl/Manifest. Keep these pinned together with
# CYRUS_VERSION / the Gentoo patchset revision in deps-cyrus-sasl.yml.
source_sha512='db15af9079758a9f385457a79390c8a7cd7ea666573dace8bf4fb01bb4b49037538d67285727d6a70ad799d2e2318f265c9372e2427de9371d626a1959dd6f78'
patches_sha512='33850bd3ac80721f2765414b19d1a3adaf92e973293910c0b19ef6fcdc3981a8abb3f4d6f487da71d1a7454375e77e3fafb892eace5aa37335841718fcc4c541'

if [[ "$version" != 2.1.28 || "$patchset" != cyrus-sasl-2.1.28-r4-patches ]]; then
  echo "Pinned Gentoo hashes need updating for version=$version patchset=$patchset" >&2
  exit 1
fi

curl -L --fail --retry 3 -o "$source_archive" \
  "https://github.com/cyrusimap/cyrus-sasl/releases/download/${source_dir}/${source_archive}"
if ! curl -L --fail --retry 3 -o "$patch_archive" \
  "https://distfiles.gentoo.org/distfiles/30/${patch_archive}"; then
  curl -L --fail --retry 3 -o "$patch_archive" \
    "https://dev.gentoo.org/~grobian/distfiles/${patch_archive}"
fi

python_bin=python3
command -v "$python_bin" >/dev/null 2>&1 || python_bin=python
"$python_bin" - "$source_archive" "$source_sha512" "$patch_archive" "$patches_sha512" <<'PY'
import hashlib
import pathlib
import sys

for path_s, expected in ((sys.argv[1], sys.argv[2]), (sys.argv[3], sys.argv[4])):
    path = pathlib.Path(path_s)
    digest = hashlib.sha512(path.read_bytes()).hexdigest()
    if digest != expected:
        raise SystemExit(f"SHA512 mismatch for {path}:\n expected {expected}\n      got {digest}")
    print(f"verified SHA512: {path}")
PY

rm -rf "$source_dir" "$patch_dir"
tar -xzf "$source_archive"
mkdir -p "$patch_dir"
tar -xJf "$patch_archive" -C "$patch_dir"

patch_count=$(find "$patch_dir" -type f \( -name '*.patch' -o -name '*.diff' \) | wc -l | tr -d ' ')
if [[ "$patch_count" == 0 ]]; then
  echo "Gentoo patch archive did not contain any patch files" >&2
  exit 1
fi

echo "Applying $patch_count Gentoo Cyrus SASL patches"
root=$PWD
while IFS= read -r patch_file; do
  echo "  $(basename "$patch_file")"
  if command -v patch >/dev/null 2>&1; then
    (cd "$source_dir" && patch -p1 < "$root/$patch_file")
  else
    # Git for Windows is always present on GitHub-hosted Windows runners.
    # This fallback keeps source preparation usable if MSYS 'patch' is absent.
    git apply --unsafe-paths --whitespace=nowarn --directory="$source_dir" "$patch_file"
  fi
done < <(find "$patch_dir" -type f \( -name '*.patch' -o -name '*.diff' \) -print | LC_ALL=C sort)

if [[ "$mode" == '--autoreconf' ]]; then
  # Mirror Gentoo's src_prepare adjustments before eautoreconf.
  "$python_bin" - "$source_dir" <<'PY'
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
for rel in ("plugins/Makefile.am", "plugins/Makefile.in"):
    path = src / rel
    lines = path.read_text().splitlines(keepends=True)
    out = []
    changed = False
    for line in lines:
        if line.startswith("sasldir ="):
            ending = "\n" if line.endswith("\n") else ""
            line = "sasldir = $(plugindir)" + ending
            changed = True
        out.append(line)
    if not changed:
        raise SystemExit(f"Gentoo sasldir adjustment did not match {path}")
    path.write_text("".join(out))

configure = src / "configure.ac"
text = configure.read_text()
old = "AC_CONFIG_MACRO_DIR("
if old not in text:
    raise SystemExit("Gentoo AC_CONFIG_MACRO_DIR adjustment did not match configure.ac")
configure.write_text(text.replace(old, "AC_CONFIG_MACRO_DIRS("))
PY
  (cd "$source_dir" && autoreconf -fiv)
fi
