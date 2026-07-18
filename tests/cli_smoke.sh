#!/usr/bin/env bash
# CLI-level checks that need the actual built binary rather than
# calling internal functions directly — covers argv handling that the
# C unit tests don't reach (main.c's dispatch, not commands/*.c).
set -euo pipefail

BIN="${1:-./khm}"
if [ ! -x "$BIN" ]; then
    echo "usage: $0 <path-to-khm-binary>" >&2
    exit 2
fi

fail=0
check() {
    local desc="$1"; shift
    if "$@"; then
        echo "  ok    $desc"
    else
        echo "  FAIL  $desc"
        fail=1
    fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
touch "$tmp/known_hosts"

# --version / -v print something and exit 0
check "--version exits 0"        bash -c "'$BIN' --version >/dev/null"
check "-v exits 0"                bash -c "'$BIN' -v >/dev/null"
check "--version prints 'khm '"   bash -c "'$BIN' --version | grep -q '^khm '"
check "-v and --version agree"    bash -c "[ \"\$('$BIN' -v)\" = \"\$('$BIN' --version)\" ]"

# ls is a true alias for list: same exit code and same output on an
# identical known_hosts file.
check "ls exits same as list"     bash -c "'$BIN' list --file '$tmp/known_hosts' >/dev/null; a=\$?; '$BIN' ls --file '$tmp/known_hosts' >/dev/null; b=\$?; [ \"\$a\" = \"\$b\" ]"
check "ls output == list output"  bash -c "diff <('$BIN' list --file '$tmp/known_hosts') <('$BIN' ls --file '$tmp/known_hosts')"
check "ls --json works too"       bash -c "'$BIN' ls --file '$tmp/known_hosts' --json | head -c1 | grep -q '\['"

if [ "$fail" -ne 0 ]; then
    echo "some CLI checks failed" >&2
    exit 1
fi
echo "all CLI checks passed"
