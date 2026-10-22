#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds a signed release of `declass` from a clean checkout.
#
#   tools/release.sh <version> --key <ssh signing key> [--apple-identity ID] [--out DIR]
#
# <version> must equal the workspace version in Cargo.toml. The key is the
# operator's SSH signing key (private key, or its public key while the private
# key is loaded in ssh-agent); DECLASS_RELEASE_KEY may name it instead of --key.
# No key is generated, and a key inside this repository is refused.
# --apple-identity (a macOS host only) also signs the binary with a Developer ID
# Application certificate in the keychain, named as `security find-identity -v
# -p codesigning` lists it (its name or SHA-1 hash), with the hardened runtime
# and a secure timestamp, before anything is summed. Notarize the disk image
# made from the release (tools/package-dmg.sh --notary-profile).
#
# Steps: the full gate (tools/gate.sh); `cargo build --release --locked` for the
# host target; licenses and vendored source; SBOM; BUILDINFO.txt (version, commit,
# toolchain); SHA256SUMS over every file; SHA256SUMS.sig, a detached SSH
# signature (`ssh-keygen -Y sign`, namespace declass-release). Output:
# dist/declass-<version>/ unless --out is given. Check with tools/verify-release.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(pwd -P)

die() {
    echo "release: $*" >&2
    exit 1
}
usage() {
    sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'
}

version=""
key="${DECLASS_RELEASE_KEY:-}"
apple_identity=""
out=""
while [ $# -gt 0 ]; do
    case "$1" in
    -h | --help)
        usage
        exit 0
        ;;
    --key)
        [ $# -ge 2 ] || die "--key needs a path"
        key="$2"
        shift 2
        ;;
    --apple-identity)
        [ $# -ge 2 ] && [ -n "$2" ] || die "--apple-identity needs a code-signing identity"
        apple_identity="$2"
        shift 2
        ;;
    --out)
        [ $# -ge 2 ] || die "--out needs a directory"
        out="$2"
        shift 2
        ;;
    -*) die "unknown option $1" ;;
    *)
        [ -z "$version" ] || die "one version only"
        version="$1"
        shift
        ;;
    esac
done

[ -n "$version" ] || {
    usage >&2
    exit 2
}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "version $version is not x.y.z[-pre]"
workspace_version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
[ "$version" = "$workspace_version" ] ||
    die "version $version does not match the workspace version $workspace_version in Cargo.toml"

# The signing key is the operator's; the script never creates one.
[ -n "$key" ] || die "a signing key is required: --key <path to your SSH signing key> (or DECLASS_RELEASE_KEY)"
[ -f "$key" ] && [ -r "$key" ] || die "signing key $key is not a readable file"
key_abs="$(cd "$(dirname "$key")" && pwd -P)/$(basename "$key")"
case "$key_abs" in
"$repo"/*) die "signing key $key is inside the repository; keep keys outside it" ;;
esac
command -v ssh-keygen >/dev/null || die "ssh-keygen is required for signing"

target=$(rustc -vV | sed -n 's/^host: //p')
# The Apple identity is checked before any work: only Developer ID Application
# signs software distributed outside the App Store (an Apple Development
# certificate does not). Signing uses its hash, which two certificates of the
# same name cannot make ambiguous.
apple_name=""
apple_hash=""
if [ -n "$apple_identity" ]; then
    case "$target" in
    *-apple-darwin) ;;
    *) die "--apple-identity signs macOS builds; this host builds $target" ;;
    esac
    command -v codesign >/dev/null && command -v security >/dev/null ||
        die "Apple signing needs codesign and security (Xcode command-line tools)"
    while IFS= read -r line; do
        [[ "$line" =~ ^\ *[0-9]+\)\ ([0-9A-F]{40})\ \"(.*)\"$ ]] || continue
        if [ "${BASH_REMATCH[1]}" = "$apple_identity" ] || [ "${BASH_REMATCH[2]}" = "$apple_identity" ]; then
            apple_hash=${BASH_REMATCH[1]}
            apple_name=${BASH_REMATCH[2]}
            break
        fi
    done < <(security find-identity -v -p codesigning)
    [ -n "$apple_name" ] ||
        die "no valid code-signing identity \"$apple_identity\" in the keychain (security find-identity -v -p codesigning)"
    case "$apple_name" in
    "Developer ID Application: "*) ;;
    *) die "\"$apple_name\" is not a Developer ID Application identity; only Developer ID signs software distributed outside the App Store" ;;
    esac
fi

[ -z "$(git status --porcelain)" ] ||
    die "the working tree has uncommitted changes; release from a clean commit"
commit=$(git rev-parse HEAD)

out="${out:-dist/declass-$version}"
[ ! -e "$out" ] || die "$out already exists"

echo "== gate"
tools/gate.sh

echo "== build ($target)"
# DECLASS_RELEASE_BUILD marks the binary as a release build (`declass doctor` then
# warns when no release signing keys are present).
# Sources are named /src/... and dependencies /cargo/... in the binary, never
# by this machine's directories (which include the operator's home).
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$repo=/src --remap-path-prefix=$cargo_home=/cargo"
DECLASS_RELEASE_BUILD=1 cargo build --release --locked -p declass-cli --bin declass --target "$target"
target_dir=$(cargo metadata --format-version 1 --no-deps --offline |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
[ -n "$target_dir" ] || die "cannot find cargo's target directory"

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
mkdir -p "$out"
echo "== corresponding source"
tools/source-release.sh "$out/declass-$version-source.tar.gz"
binary="declass-$version-$target"
cp "$target_dir/$target/release/declass" "$out/$binary"

# Signing changes the binary's bytes, so it comes before the checksums.
apple_signature=none
if [ -n "$apple_name" ]; then
    echo "== Apple signing ($apple_name)"
    codesign --force --options runtime --timestamp --sign "$apple_hash" "$out/$binary"
    codesign --verify --strict --verbose=2 "$out/$binary"
    details=$(codesign -dvv "$out/$binary" 2>&1)
    grep -qxF "Authority=$apple_name" <<<"$details" || die "the binary's signature is not by $apple_name"
    grep -q '^Timestamp=' <<<"$details" || die "the binary's signature has no secure timestamp"
    grep -q '^CodeDirectory .*flags=.*(runtime)' <<<"$details" || die "the binary's signature lacks the hardened runtime"
    [ "$("$out/$binary" --version)" = "declass $version" ] || die "the signed binary does not run"
    apple_signature="$apple_name (hardened runtime, secure timestamp)"
fi

echo "== SBOM"
tools/sbom.sh --target "$target" --out "$out/declass-$version.cdx.json"

cat >"$out/BUILDINFO.txt" <<INFO
declass $version
commit $commit
target $target
$(rustc -V)
$(cargo -V)
source_date_epoch $SOURCE_DATE_EPOCH
apple_signature $apple_signature
built with: RUSTFLAGS='--remap-path-prefix=<source>=/src --remap-path-prefix=<cargo home>=/cargo' DECLASS_RELEASE_BUILD=1 cargo build --release --locked -p declass-cli --bin declass --target $target
INFO

echo "== licenses"
cp LICENSE NOTICE LICENSES.md "$out/"
cp crates/declass-boundary/rules/LICENSE.gitleaks "$out/LICENSE.gitleaks"
cp crates/declass-boundary/rules/NOTICE "$out/NOTICE.gitleaks"
cat >"$out/SOURCE.txt" <<INFO
Corresponding Source for declass $version ($target)
Commit: $commit
Archive: declass-$version-source.tar.gz (distributed beside this binary)

Extract the archive and enter declass-source/. Locked Cargo workspace dependencies
are in vendor/; license notices are in vendor/ and licenses/third-party/.
Install the Rust toolchain recorded in BUILDINFO.txt and the platform's C/C++
build tools, then build without downloading Cargo dependencies:

  DECLASS_RELEASE_BUILD=1 cargo build --release --frozen -p declass-cli --bin declass --target $target

The binary is target/$target/release/declass. See tools/install.sh for installation.
Publish this source archive, LICENSE, NOTICE, LICENSES.md, LICENSE.gitleaks and
NOTICE.gitleaks alongside the binary. Preserve their availability to recipients.
INFO

[ "$apple_signature" = none ] || cat >>"$out/SOURCE.txt" <<INFO

The published binary also carries an Apple Developer ID signature (BUILDINFO.txt),
so its bytes differ from a binary built from this source.
INFO

echo "== checksums and signature"
if command -v shasum >/dev/null; then
    sha256() { shasum -a 256 "$@"; }
else
    sha256() { sha256sum "$@"; }
fi
(
    cd "$out"
    sha256 "$binary" "declass-$version.cdx.json" BUILDINFO.txt LICENSE NOTICE LICENSES.md \
        LICENSE.gitleaks NOTICE.gitleaks "declass-$version-source.tar.gz" SOURCE.txt >SHA256SUMS
)
ssh-keygen -Y sign -f "$key" -n declass-release "$out/SHA256SUMS"
[ -s "$out/SHA256SUMS.sig" ] || die "signing produced no signature"

echo
echo "release $version written to $out:"
ls -1 "$out"
echo
echo "signed by: $(ssh-keygen -l -f "$key" 2>/dev/null || echo "(key fingerprint unavailable)")"
[ "$apple_signature" = none ] || echo "Apple signature: $apple_signature"
echo "Publish SHA256SUMS.sig with the files, and your allowed-signers line"
echo "  <identity> namespaces=\"declass-release\" <public key>"
echo "through a channel users already trust. Verify: tools/verify-release.sh $out"
