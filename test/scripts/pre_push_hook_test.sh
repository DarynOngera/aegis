#!/bin/sh
# Tests examples/hooks/pre-push with a fake `dep-guard` on PATH.
# Run from anywhere:  sh test/scripts/pre_push_hook_test.sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
HOOK=$(cd "$HERE/../../examples/hooks" && pwd)/pre-push
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAILS=0
ok() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }

mkdir -p "$TMP/bin"
cat >"$TMP/bin/dep-guard" <<'EOS'
#!/bin/sh
echo called >>"$FAKE_LOG"
exit "${FAKE_EXIT:-0}"
EOS
chmod +x "$TMP/bin/dep-guard"

proj="$TMP/proj"
mkdir -p "$proj"
cd "$proj"
git init -q -b main
git config user.email t@example.com
git config user.name t
git config commit.gpgsign false
echo '%{}' >mix.lock
git add . && git commit -q -m base
git update-ref refs/remotes/origin/main HEAD
git checkout -q -b feature

run() { FAKE_LOG="$TMP/log" PATH="$TMP/bin:$PATH" sh "$HOOK"; }

: >"$TMP/log"
if run >/dev/null 2>&1 && [ ! -s "$TMP/log" ]; then ok "unchanged mix.lock: no scan, push allowed"; else fail "unchanged mix.lock: no scan, push allowed"; fi

echo '%{"a": 1}' >mix.lock && git commit -q -am change
: >"$TMP/log"
if run >/dev/null 2>&1 && [ -s "$TMP/log" ]; then ok "changed mix.lock: scan runs"; else fail "changed mix.lock: scan runs"; fi

: >"$TMP/log"
if FAKE_EXIT=1 run >/dev/null 2>&1; then fail "a failing scan blocks the push"; else ok "a failing scan blocks the push"; fi

: >"$TMP/log"
if DEP_GUARD_BASE=origin/nope run >/dev/null 2>&1 && [ ! -s "$TMP/log" ]; then ok "no base branch: push allowed, no scan"; else fail "no base branch: push allowed, no scan"; fi

if [ "$FAILS" -gt 0 ]; then echo "$FAILS check(s) failed"; exit 1; fi
echo "all checks passed"
