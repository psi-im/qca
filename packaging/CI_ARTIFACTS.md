# QCA3 CI artifacts

The workflows are intentionally split by responsibility.

## Build and test

`.github/workflows/ci.yml` verifies that QCA builds on Linux, Windows, macOS and
Android. The required provider set is fixed to `ossl;cyrus-sasl`. This workflow
does not publish SDK or package artifacts.

Linux uses the distribution Cyrus SASL. Windows, macOS and Android consume the
static dependency bundles described below.

## Cyrus SASL dependency bundles

`.github/workflows/deps-cyrus-sasl.yml` is a manually triggered dependency
build. It creates the prerelease tag
`deps-cyrus-sasl-${CYRUS_VERSION}-${CYRUS_REVISION}` and publishes one static
bundle per non-Linux target as release assets.

The bundle contains a static Cyrus SASL with only the mechanisms QCA needs:

- PLAIN
- SCRAM
- DIGEST-MD5

On macOS and Android the upstream autotools static-plugin support is used with
`-fPIC`. Android is pinned to NDK r27c (27.2.12479018), matching Qt 6.10. On Windows `packaging/cyrus-sasl/patch-windows-static.py` adds a real
`libsasl2-static.lib` target to the upstream NMake build and explicitly compiles
only `STATIC_PLAIN`, `STATIC_SCRAM` and `STATIC_DIGESTMD5`. Upstream's
`NO_STATIC_PLUGINS` define is intentionally retained so its Windows `config.h`
does not implicitly enable unrelated mechanisms.

Existing release assets are never overwritten. Bump `CYRUS_REVISION` whenever
the dependency recipe changes.

Run this workflow once before running non-Linux QCA CI/package jobs for a new
dependency revision.

## Packages and SDKs

`.github/workflows/packages.yml` publishes Actions artifacts suitable for
consumer CI:

- Ubuntu 24.04 `.deb` packages:
  - `libqca3-qt6-3`
  - `libqca3-qt6-dev`
  - `libqca3-qt6-plugins`
  - `qca3-qt6-utils`
- Windows x64 QCA3 SDK archive
- macOS arm64 and x86_64 QCA3 SDK archives
- Android QCA3 SDK archives for arm64-v8a, armeabi-v7a, x86_64 and x86

The packaging jobs require both `qca-ossl` and `qca-cyrus-sasl`. Non-Linux
jobs also verify that `qca-cyrus-sasl` has no shared Cyrus SASL runtime
dependency.
