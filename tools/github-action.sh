#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# The steps of the Declass GitHub Action (action.yml). Every input comes from
# the environment, so the steps also run outside GitHub.
#
#   tools/github-action.sh install
#       Installs a Declass release with tools/install-release.sh from this
#       checkout. The SSH signature is checked against docs/declass-release.pub
#       of this checkout (the commit the workflow pinned), and every checksum,
#       before anything downloaded runs. DECLASS_VERSION picks the release
#       (x.y.z); empty means the version of this checkout. Installs under
#       RUNNER_TEMP and sets DECLASS_BIN through GITHUB_ENV.
#
#   tools/github-action.sh exposure
#       Runs `declass exposure --sarif` with DECLASS_BIN on EXPOSURE_PATH
#       (default .), writes EXPOSURE_SARIF (default declass-exposure.sarif),
#       fails at EXPOSURE_FAIL_ON (default never) and with EXPOSURE_HISTORY=true
#       reads git history too. With EXPOSURE_BASE_SHA (a pull request's base
#       commit) and EXPOSURE_PROJECT_CONFIG=base (the default), the project's
#       .declass/ is the base commit's while it runs, so a pull request cannot
#       loosen its own gate. Sets the outputs sarif-file and exit-code, and adds
#       the text report (paths and counts, never values) to the job summary.
set -euo pipefail

# The first release with `declass exposure --sarif`, `--output` and `--fail-on`.
MIN_VERSION=0.4.0
# docs/declass-release.pub (docs/INSTALLATION.md, "Signed releases").
KEY_FINGERPRINT=SHA256:sNU36mHF7ZWVl1UKd0nS1PnY07hDy/mRNC0U/aaMEqU

here="$(cd "$(dirname "$0")" && pwd -P)"
root="$(dirname "$here")"

# Text for the data of a workflow command: a line break cannot end it early
# and start a command of its own.
escape() {
    local s=${1//'%'/'%25'}
    s=${s//$'\r'/'%0D'}
    s=${s//$'\n'/'%0A'}
    printf '%s' "$s"
}

fail() {
    printf '::error title=Declass exposure::%s\n' "$(escape "$*")"
    exit 1
}

# Whether version $1 (x.y.z[-pre]) is $2 (x.y.z) or later. As in semantic
# versioning, a pre-release comes before its release: 0.4.0-rc.1 is older
# than 0.4.0.
at_least() {
    local IFS=.
    local -a have want
    read -r -a have <<<"${1%%-*}"
    read -r -a want <<<"$2"
    for i in 0 1 2; do
        if ((10#${have[i]:-0} != 10#${want[i]:-0})); then
            ((10#${have[i]:-0} > 10#${want[i]:-0}))
            return
        fi
    done
    [ "$1" = "${1%%-*}" ]
}

# A single-line input: it is written to GITHUB_OUTPUT and passed to declass.
one_line() {
    case "$2" in *$'\n'* | *$'\r'*) fail "$1 must be one line" ;; esac
}

install() {
    local version="${DECLASS_VERSION:-}" from_checkout=false
    if [ -z "$version" ]; then
        version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
        from_checkout=true
    fi
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
        fail "version must be a release number such as $MIN_VERSION, not '$version'"
    if ! at_least "$version" "$MIN_VERSION"; then
        if $from_checkout; then
            fail "this action's commit is Declass $version, and declass exposure --sarif arrived in $MIN_VERSION: use the action from a release tag (maximpri/declass@v$MIN_VERSION or later) or set the version input"
        fi
        fail "declass exposure --sarif needs Declass $MIN_VERSION or later; version $version is older (a pre-release comes before its release)"
    fi
    [ -n "${RUNNER_TEMP:-}" ] || fail "RUNNER_TEMP is not set"
    local dir="$RUNNER_TEMP/declass-action"
    mkdir -p "$dir"
    # The signer comes from this checkout, never from the download.
    local key="$root/docs/declass-release.pub"
    local fingerprint
    fingerprint=$(ssh-keygen -l -f "$key" | awk '{print $2}') || fail "cannot read $key"
    [ "$fingerprint" = "$KEY_FINGERPRINT" ] || fail "$key is not the Declass release key"
    local type data
    read -r type data _ <"$key"
    printf 'declass-release namespaces="declass-release" %s %s\n' "$type" "$data" >"$dir/allowed_signers"
    DECLASS_INSTALL_DIR="$dir/bin" DECLASS_DATA_DIR="$dir/share" \
        bash "$here/install-release.sh" "$version" --signers "$dir/allowed_signers" --no-modify-path ||
        fail "installing Declass $version failed (see above)"
    local bin="$dir/bin/declass" reported
    reported=$("$bin" --version) || fail "the installed declass does not run"
    [ "$reported" = "declass $version" ] || fail "the installed declass reports '$reported', not $version"
    if [ -n "${GITHUB_ENV:-}" ]; then
        printf 'DECLASS_BIN=%s\n' "$bin" >>"$GITHUB_ENV"
    fi
    if [ -n "${GITHUB_PATH:-}" ]; then
        printf '%s\n' "$dir/bin" >>"$GITHUB_PATH"
    fi
    printf 'Installed %s, signature and checksums verified\n' "$reported"
}

# Where the project's own .declass/ waits while the base commit's is used.
moved=""
project=""

restore_project() {
    [ -n "$moved" ] || return 0
    rm -rf -- "$project/.declass"
    if [ -e "$moved/.declass" ] || [ -L "$moved/.declass" ]; then
        mv -- "$moved/.declass" "$project/.declass"
    fi
    rm -rf -- "$moved"
    moved=""
}

# Uses the base commit's .declass/config.toml (and derived.json) in place of
# the checkout's .declass/ until the step ends: what a pull request changes
# there applies once it is merged, not to its own gate.
use_base_config() {
    local base=$2
    project=$1
    [[ "$base" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || fail "the base commit '$base' is not a commit id"
    git -C "$project" cat-file -e "$base^{commit}" 2>/dev/null ||
        fail "the pull request's base commit is not in this checkout, so the gate cannot use its .declass/config.toml: check out with fetch-depth: 0, or set project-config: checkout"
    moved=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/declass-project.XXXXXXXX")
    trap restore_project EXIT
    if [ -e "$project/.declass" ] || [ -L "$project/.declass" ]; then
        mv -- "$project/.declass" "$moved/.declass"
    fi
    local file
    for file in config.toml derived.json; do
        if git -C "$project" cat-file -e "$base:./.declass/$file" 2>/dev/null; then
            mkdir -p -- "$project/.declass"
            git -C "$project" cat-file blob "$base:./.declass/$file" >"$project/.declass/$file"
        fi
    done
}

exposure() {
    local bin="${DECLASS_BIN:-}"
    [ -n "$bin" ] && [ -x "$bin" ] || fail "Declass is not installed (run the install step first)"
    local reported version
    reported=$("$bin" --version) || fail "declass does not run"
    version="${reported#declass }"
    at_least "$version" "$MIN_VERSION" ||
        fail "declass exposure --sarif needs Declass $MIN_VERSION or later; this is $reported"
    local path="${EXPOSURE_PATH:-.}" sarif="${EXPOSURE_SARIF:-declass-exposure.sarif}"
    local fail_on="${EXPOSURE_FAIL_ON:-never}" history="${EXPOSURE_HISTORY:-false}"
    local config="${EXPOSURE_PROJECT_CONFIG:-base}" base="${EXPOSURE_BASE_SHA:-}"
    one_line path "$path"
    one_line sarif-file "$sarif"
    case "$fail_on" in
    note | warning | error | never) ;;
    *) fail "fail-on must be note, warning, error or never, not '$fail_on'" ;;
    esac
    local -a args=(--workspace "$path" exposure --sarif --output "$sarif" --fail-on "$fail_on")
    case "$history" in
    true) args+=(--history) ;;
    false) ;;
    *) fail "history must be true or false, not '$history'" ;;
    esac
    case "$config" in
    base) [ -z "$base" ] || use_base_config "$path" "$base" ;;
    checkout) ;;
    *) fail "project-config must be base or checkout, not '$config'" ;;
    esac
    # A report left by an earlier step must never be uploaded as this one.
    rm -f -- "$sarif"
    mkdir -p -- "$(dirname -- "$sarif")"
    local text errors status=0 token
    text=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/declass-exposure.XXXXXXXX")
    errors=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/declass-exposure.XXXXXXXX")
    "$bin" "${args[@]}" >"$text" 2>"$errors" || status=$?
    restore_project
    # Nothing the report prints (file names, configuration notes) may act as a
    # workflow command: the runner reads none until this random token.
    token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    [ "${#token}" -eq 32 ] || fail "cannot read random bytes"
    printf '::stop-commands::%s\n' "$token"
    cat -- "$text" "$errors"
    printf '::%s::\n' "$token"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -s "$text" ]; then
        # A fence longer than any run of backticks in a file name.
        local fence
        fence=$(awk '{ while (match($0, /`+/)) { if (RLENGTH > n) n = RLENGTH; $0 = substr($0, RSTART + RLENGTH) } }
            END { s = "```"; for (i = 3; i <= n; i++) s = s "`"; print s }' "$text")
        printf '### Declass exposure\n\n%stext\n%s\n%s\n' "$fence" "$(cat -- "$text")" "$fence" >>"$GITHUB_STEP_SUMMARY"
    fi
    rm -f -- "$text" "$errors"
    [ -s "$sarif" ] || fail "declass exposure wrote no report (exit $status)"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf 'sarif-file=%s\nexit-code=%s\n' "$sarif" "$status" >>"$GITHUB_OUTPUT"
    fi
    case "$status" in
    0) ;;
    1)
        printf '::error title=Declass exposure::findings at or above --fail-on %s; see the report above\n' "$fail_on"
        exit 1
        ;;
    2)
        printf '::error title=Declass exposure::the report is incomplete; see the report above\n'
        exit 2
        ;;
    *) fail "declass exposure failed (exit $status)" ;;
    esac
}

case "${1:-}" in
install) install ;;
exposure) exposure ;;
*)
    printf 'usage: tools/github-action.sh install | exposure\n' >&2
    exit 2
    ;;
esac
