#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Wrap a verified macOS payload without changing its binary or signed manifest.
# With --apple-identity and --notary-profile, the payload's binary must already
# carry that Developer ID signature (tools/release.sh --apple-identity); the
# image is then signed, notarized by Apple (an upload), stapled and assessed by
# Gatekeeper before its checksum is made. Store the notary credentials first:
# xcrun notarytool store-credentials PROFILE (it asks for the password).
set -euo pipefail
export COPYFILE_DISABLE=1
umask 077
fail() { printf 'package-dmg: %s\n' "$*" >&2; exit 1; }
usage() { echo 'usage: package-dmg.sh RELEASE_DIR --out FILE.dmg [--unsigned | --key KEY --signers FILE] [--apple-identity ID --notary-profile PROFILE]'; }
release="" out="" signers="" key="" mode=unsigned apple_identity="" notary_profile=""
unsigned_requested=false
while [ $# -gt 0 ]; do
    case "$1" in
        --out|--signers|--key|--apple-identity|--notary-profile) [ $# -ge 2 ] && [ -n "$2" ] || fail "$1 requires a value"; case "$1" in --out) out=$2 ;; --signers) signers=$2 ;; --key) key=$2 ;; --apple-identity) apple_identity=$2 ;; --notary-profile) notary_profile=$2 ;; esac; shift 2 ;;
        --unsigned) unsigned_requested=true; shift ;;
        --help|-h) usage; exit 0 ;;
        -*) fail "unknown option: $1" ;;
        *) [ -z "$release" ] || fail 'specify one release directory'; release=$1; shift ;;
    esac
done
[ -n "$release" ] && [ -n "$out" ] || { usage >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || fail 'DMG packaging requires macOS'
command -v hdiutil >/dev/null || fail 'hdiutil is required'
[ -d "$release" ] && [ ! -L "$release" ] || fail 'release must be an ordinary directory'
[ ! -e "$out" ] && [ ! -L "$out" ] || fail 'output already exists'
case "$out" in *.dmg) ;; *) fail 'output must end in .dmg' ;; esac
if [ -n "$key" ]; then
    $unsigned_requested && fail '--unsigned and --key are mutually exclusive'
    [ -f "$key" ] && [ -r "$key" ] && [ -f "$signers" ] || fail 'signing needs an existing readable key and trusted --signers FILE'
    mode=signed
    key=$(cd "$(dirname "$key")" && pwd -P)/$(basename "$key")
    signers=$(cd "$(dirname "$signers")" && pwd -P)/$(basename "$signers")
else
    [ -z "$signers" ] || fail '--signers requires --key for authenticated DMG packaging'
fi
# An Apple-signed image is notarized too: Gatekeeper blocks a downloaded image
# that is signed but not notarized, so signing alone would only mislead.
apple_name="" apple_hash=""
if [ -n "$apple_identity" ] || [ -n "$notary_profile" ]; then
    [ -n "$apple_identity" ] && [ -n "$notary_profile" ] || fail '--apple-identity and --notary-profile go together'
    for tool in codesign security xcrun spctl; do
        command -v "$tool" >/dev/null || fail "Apple signing needs $tool (Xcode command-line tools)"
    done
    while IFS= read -r line; do
        [[ "$line" =~ ^\ *[0-9]+\)\ ([0-9A-F]{40})\ \"(.*)\"$ ]] || continue
        if [ "${BASH_REMATCH[1]}" = "$apple_identity" ] || [ "${BASH_REMATCH[2]}" = "$apple_identity" ]; then
            apple_hash=${BASH_REMATCH[1]}
            apple_name=${BASH_REMATCH[2]}
            break
        fi
    done < <(security find-identity -v -p codesigning)
    [ -n "$apple_name" ] || fail "no valid code-signing identity \"$apple_identity\" in the keychain"
    case "$apple_name" in
        "Developer ID Application: "*) ;;
        *) fail "\"$apple_name\" is not a Developer ID Application identity" ;;
    esac
fi
tools=$(cd "$(dirname "$0")" && pwd -P)
if [ "$mode" = signed ]; then
    repo=$(cd "$tools/.." && pwd -P)
    case "$key" in "$repo"/*) fail 'keep signing keys outside the repository' ;; esac
fi
release=$(cd "$release" && pwd -P)
mkdir -p "$(dirname "$out")"
out=$(cd "$(dirname "$out")" && pwd -P)/$(basename "$out")
for path in "$out.SHA256SUMS" "$out.SHA256SUMS.sig"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail 'outer verification output already exists'
done
# A sibling lock reserves the output without truncating a preexisting image.
lock="$out.lock"
mkdir "$lock" 2>/dev/null || fail 'output is already reserved'
scratch=""
cleanup() { [ -z "$scratch" ] || rm -rf "$scratch"; rmdir "$lock" 2>/dev/null || true; }
trap cleanup EXIT
scratch=$(mktemp -d "${TMPDIR:-/tmp}/declass-dmg.XXXXXXXX")
volume="$scratch/volume"
mkdir "$volume" "$volume/payload"
# Reject links/directories before copying; verification is repeated on the copy.
for file in "$release"/* "$release"/.[!.]* "$release"/..?*; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    [ -f "$file" ] && [ ! -L "$file" ] || fail 'release contains a nonregular artifact'
    cp -p "$file" "$volume/payload/"
done
cp "$tools/dmg/Install Declass.command" "$volume/Install Declass.command"
cp "$tools/verify-release.sh" "$volume/verify-release.sh"
cp "$tools/verify-checksums.sh" "$volume/verify-checksums.sh"
printf '%s\n' "$mode" >"$volume/INSTALL-MODE"
chmod 755 "$volume/Install Declass.command" "$volume/verify-release.sh" "$volume/verify-checksums.sh"
if [ "$mode" = signed ]; then
    /bin/bash "$volume/Install Declass.command" --verify-only --signers "$signers"
else
    /bin/bash "$volume/Install Declass.command" --verify-only --unsigned
fi
version=$(sed -n 's/^declass //p' "$volume/payload/BUILDINFO.txt")
target=$(sed -n 's/^target //p' "$volume/payload/BUILDINFO.txt")
apple="No Apple code signing or notarization is performed or claimed. Apple signing
must precede creation of the payload checksums and release signature."
if [ -n "$apple_name" ]; then
    # Notarization checks the binary inside too: it must already be signed, by
    # the same identity, with the hardened runtime and a timestamp.
    binary="$volume/payload/declass-$version-$target"
    codesign --verify --strict "$binary" 2>/dev/null ||
        fail 'the payload binary has no valid Apple signature; build the release with tools/release.sh --apple-identity'
    details=$(codesign -dvv "$binary" 2>&1)
    grep -qxF "Authority=$apple_name" <<<"$details" || fail "the payload binary is not signed by $apple_name"
    grep -q '^Timestamp=' <<<"$details" || fail 'the payload binary has no secure timestamp'
    grep -q '^CodeDirectory .*flags=.*(runtime)' <<<"$details" || fail 'the payload binary lacks the hardened runtime'
    apple="The binary and this image are signed by $apple_name
and notarized by Apple; the notarization ticket is stapled to the image. The
SSH release signature remains the way to authenticate the payload."
fi
cat >"$volume/README.txt" <<INFO
Declass $version ($target) — CLI/TUI installer
Release verification mode: $mode

Open Install Declass.command to install to your own ~/.local/bin (no sudo).
All payload files, including full corresponding source and licenses, are retained
under ~/.local/share/declass/releases. No network access is needed by this installer.
The payload/ directory contains the original release files and checksums.

Unsigned mode requires explicit confirmation or --unsigned. Checksums do not
identify a publisher. Signed mode verifies the payload's SSH release signature
using your independently obtained ~/.config/declass/allowed_signers file (or
DECLASS_CONFIG_HOME/allowed_signers); --signers FILE selects another trusted file.
This image does not supply its own trusted keys. Before opening a signed image,
verify the separate DMG.SHA256SUMS.sig (SSH namespace declass-release) with your
independently trusted signer, then the DMG checksum. That authenticates the whole
image including this installer. SSH signatures are not Apple authentication.

$apple This tool
never strips quarantine or bypasses Gatekeeper. If macOS blocks an unsigned
candidate, stop and use only an installation method approved for your machine.
See SOURCE.txt, LICENSE, NOTICE and LICENSES.md inside payload/ for distribution.
INFO
# Normalize mounted permissions independently of the packager's umask/ownership.
# Only staging modes change; signed file bytes and the original payload stay intact.
chmod 755 "$volume" "$volume/payload"
for file in "$volume/payload"/* "$volume/payload"/.[!.]* "$volume/payload"/..?*; do
    [ -f "$file" ] || continue
    chmod 644 "$file"
done
chmod 644 "$volume/README.txt" "$volume/INSTALL-MODE"
chmod 755 "$volume/payload/declass-$version-$target"
hdiutil create -quiet -srcfolder "$volume" -volname "Declass $version $mode" -fs HFS+ -format UDZO "$scratch/candidate.dmg"
if [ -n "$apple_name" ]; then
    # Signing, notarizing and stapling change the image, so they come before
    # its checksum and SSH signature.
    codesign --force --timestamp --sign "$apple_hash" "$scratch/candidate.dmg"
    codesign --verify --strict "$scratch/candidate.dmg" || fail 'the image signature did not verify'
    echo 'package-dmg: submitting the image to Apple for notarization (this uploads it)'
    xcrun notarytool submit "$scratch/candidate.dmg" --keychain-profile "$notary_profile" \
        --wait --output-format json >"$scratch/notary.json" || true
    notary_status=$(sed -n 's/.*"status" *: *"\([^"]*\)".*/\1/p' "$scratch/notary.json" | tail -n 1)
    notary_id=$(sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' "$scratch/notary.json" | tail -n 1)
    [ "$notary_status" = Accepted ] ||
        fail "notarization ${notary_status:-failed}${notary_id:+; see xcrun notarytool log $notary_id --keychain-profile $notary_profile}"
    xcrun stapler staple "$scratch/candidate.dmg" || fail 'stapling the notarization ticket failed'
    xcrun stapler validate "$scratch/candidate.dmg" || fail 'the stapled ticket did not validate'
    spctl --assess --type open --context context:primary-signature -v "$scratch/candidate.dmg" ||
        fail 'Gatekeeper does not accept the image'
fi
# Hard-link publication is exclusive: a late competing file is never replaced.
cp "$scratch/candidate.dmg" "$lock/candidate.dmg"
ln "$lock/candidate.dmg" "$out" || fail 'output appeared while packaging'
rm "$lock/candidate.dmg"
if command -v shasum >/dev/null; then
    (cd "$(dirname "$out")" && shasum -a 256 "$(basename "$out")") >"$lock/checksums"
else
    (cd "$(dirname "$out")" && sha256sum "$(basename "$out")") >"$lock/checksums"
fi
if [ "$mode" = signed ]; then
    ssh-keygen -Y sign -f "$key" -n declass-release "$lock/checksums"
    principals=$(ssh-keygen -Y find-principals -s "$lock/checksums.sig" -f "$signers") || fail 'outer signature has no trusted signer'
    verified=false
    while IFS= read -r identity; do
        if ssh-keygen -Y verify -f "$signers" -I "$identity" -n declass-release -s "$lock/checksums.sig" <"$lock/checksums" >/dev/null 2>&1; then verified=true; break; fi
    done <<<"$principals"
    $verified || fail 'outer signature did not verify'
fi
ln "$lock/checksums" "$out.SHA256SUMS" || fail 'checksum output appeared while packaging'
rm "$lock/checksums"
if [ "$mode" = signed ]; then
    ln "$lock/checksums.sig" "$out.SHA256SUMS.sig" || fail 'signature output appeared while packaging'
    rm "$lock/checksums.sig"
fi
if [ -n "$apple_name" ]; then
    printf 'DMG (%s payload; signed by %s, notarized and stapled): %s\n' "$mode" "$apple_name" "$out"
else
    printf 'DMG (%s payload; no Apple authentication claimed): %s\n' "$mode" "$out"
fi
