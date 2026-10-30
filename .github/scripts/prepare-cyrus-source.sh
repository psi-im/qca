#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: prepare-cyrus-source.sh VERSION [--autoreconf]}
mode=${2:-}
source_dir="cyrus-sasl-${version}"
repository=${CYRUS_REPOSITORY:?CYRUS_REPOSITORY must identify the source repository}
commit=${CYRUS_COMMIT:?CYRUS_COMMIT must be a full commit SHA}

if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'CYRUS_COMMIT must be a full lowercase commit SHA' >&2
  exit 1
fi
if [[ -e "$source_dir" ]]; then
  echo "Source directory already exists: $source_dir" >&2
  exit 1
fi

git init "$source_dir"
git -C "$source_dir" remote add origin "https://github.com/${repository}.git"
git -C "$source_dir" fetch --depth=1 origin "$commit"
git -C "$source_dir" checkout --detach FETCH_HEAD
test "$(git -C "$source_dir" rev-parse HEAD)" = "$commit"

if [[ "$mode" == '--autoreconf' ]]; then
  python_bin=python3
  command -v "$python_bin" >/dev/null 2>&1 || python_bin=python
  "$python_bin" - "$source_dir" <<'PY'
import pathlib
import sys

# The upstream static recipe appends mechanisms to the top-level archive,
# then replaces that archive with a symlink to .libs. Append to the actual
# PIC archive that is installed and linked into QCA's shared provider.
path = pathlib.Path(sys.argv[1]) / "lib/Makefile.am"
text = path.read_text()
old = "\t$(AR) cru $@ $(SASL_STATIC_OBJS)\n"
new = "\t$(AR) cru .libs/$@ $(SASL_STATIC_OBJS)\n"
if text.count(old) != 1:
    raise SystemExit(f"{path}: expected exactly one static-archive recipe")
path.write_text(text.replace(old, new))
PY
  (cd "$source_dir" && autoreconf -fiv)
elif [[ -n "$mode" ]]; then
  echo "Unknown source preparation mode: $mode" >&2
  exit 1
fi
