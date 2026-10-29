#!/bin/sh
# Tests scripts/dep-guard with a fake `docker` so no container or network is needed.
# Run from anywhere:  sh test/scripts/dep_guard_wrapper_test.sh
set -eu

# Start from a "local" environment. CI runners set GITHUB_ACTIONS and friends, which would switch
# the script under test into CI mode; the tests that need CI mode set their own values.
unset GITHUB_ACTIONS GITHUB_REPOSITORY GITHUB_SHA GITHUB_REF_NAME GITHUB_BASE_REF CI \
  DEP_GUARD_BASE DEP_GUARD_ORG_POLICY DEP_GUARD_ORG_POLICY_SHA256 DEP_GUARD_IMAGE DEP_GUARD_OUT \
  DEP_GUARD_ROOT DEP_GUARD_REPO DEP_GUARD_COMMIT DEP_GUARD_BRANCH

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$(cd "$HERE/../../scripts" && pwd)/dep-guard
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

FAILS=0
ok() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() { # description, command...
  desc=$1
  shift
  if "$@"; then ok "$desc"; else fail "$desc"; fi
}

# A fake docker: logs every invocation, and on `scan` writes a report into the /out mount.
mkdir -p "$TMP/bin"
cat >"$TMP/bin/docker" <<'EOF'
#!/bin/sh
echo "docker $*" >>"$FAKE_DOCKER_LOG"
out=""
prev=""
for arg in "$@"; do
  case "$prev" in -v) case "$arg" in *:/out) out=${arg%:/out} ;; esac ;; esac
  prev=$arg
done
for arg in "$@"; do
  case "$arg" in
    scan) [ -n "$out" ] && [ -z "${FAKE_DOCKER_NOREPORT:-}" ] && echo '{"schema_version":"1.0"}' >"$out/report.json"; exit "${FAKE_DOCKER_EXIT:-0}" ;;
    render) echo "rendered"; exit 0 ;;
  esac
done
exit 0
EOF
chmod +x "$TMP/bin/docker"

new_project() { # name -> path of a fresh git project with main branch and a mix.lock
  dir="$TMP/$1"
  mkdir -p "$dir"
  (
    cd "$dir"
    git init -q -b main
    git config user.email t@example.com
    git config user.name t
    git config commit.gpgsign false
    echo 'defmodule P.MixProject do end' >mix.exs
    echo '%{}' >mix.lock
    git add . && git commit -q -m base
    git remote add origin "https://ci-user:s3cr3t@github.com/acme/app.git"
    git update-ref refs/remotes/origin/main HEAD
  )
  echo "$dir"
}

run() { # project, then args; env FAKE_DOCKER_* may be set by the caller
  proj=$1
  shift
  : >"$TMP/docker.log"
  (cd "$proj" && PATH="$TMP/bin:$PATH" FAKE_DOCKER_LOG="$TMP/docker.log" HOME="$TMP/home" \
    sh "$SCRIPT" "$@" >"$TMP/stdout" 2>"$TMP/stderr")
}

mkdir -p "$TMP/home"

# 1. happy path -------------------------------------------------------------------------
P=$(new_project happy)
check "a clean run exits 0" run "$P"
check "the scan runs read-only against the project" grep -q -- "--read-only" "$TMP/docker.log"
check "the project is mounted read-only" grep -q -- "$P:/workspace:ro" "$TMP/docker.log"
check "the base lock is compared (origin/main)" grep -q -- "--base-lock /out/base.lock" "$TMP/docker.log"
check "reports are written outside the project tree's tracked files" test -s "$P/.dep_guard/report.json"
check "the report directory ignores itself" test "$(cat "$P/.dep_guard/.gitignore")" = "*"
check "SARIF and the human summary are rendered from the saved report" \
  sh -c "grep -c 'render --input /out/report.json' '$TMP/docker.log' | grep -q '^2$'"
check "the human summary reaches stdout" grep -q "rendered" "$TMP/stdout"
check "credentials in the remote URL are not passed to the container" \
  sh -c "! grep -q s3cr3t '$TMP/docker.log'"
check "the repo is passed without credentials" grep -q "DEP_GUARD_REPO=https://github.com/acme/app.git" "$TMP/docker.log"

# 2. exit codes propagate and a stale report is never rendered --------------------------
P=$(new_project exits)
FAKE_DOCKER_EXIT=1 run "$P" && code=0 || code=$?
check "findings (exit 1) propagate" test "$code" = 1
FAKE_DOCKER_EXIT=2 run "$P" && code=0 || code=$?
check "an incomplete scan (exit 2) propagates" test "$code" = 2

P=$(new_project stale)
mkdir -p "$P/.dep_guard" && echo '{"old":true}' >"$P/.dep_guard/report.json"
FAKE_DOCKER_EXIT=2 FAKE_DOCKER_NOREPORT=1 run "$P" && code=0 || code=$?
check "a failed scan keeps its exit code" test "$code" = 2
check "a stale report is deleted, never rendered as if it were new" test ! -e "$P/.dep_guard/report.json"
check "a failed scan says it produced no report" grep -q "did not produce a report" "$TMP/stderr"
check "a failed scan renders nothing" sh -c "! grep -q 'render --input' '$TMP/docker.log'"

# 3. arguments are passed through; --format and --output are refused ---------------------
P=$(new_project args)
run "$P" --fail-on medium --offline --allow-skipped || true
check "scan options are passed through" grep -q -- "--fail-on medium --offline --allow-skipped" "$TMP/docker.log"
run "$P" --format json && code=0 || code=$?
check "--format is refused with exit 2" test "$code" = 2
check "--format explains why" grep -q "do not pass --format or --output" "$TMP/stderr"
run "$P" --output=x.json && code=0 || code=$?
check "--output= is refused with exit 2" test "$code" = 2

# 4. org policy ---------------------------------------------------------------------------
P=$(new_project org)
echo '%{}' >"$TMP/org.exs"
DEP_GUARD_ORG_POLICY="$TMP/org.exs" DEP_GUARD_ORG_POLICY_SHA256=abc123 run "$P" || true
check "the org policy is mounted read-only and its hash passed" \
  sh -c "grep -q -- '/policy/org.exs:ro' '$TMP/docker.log' && grep -q -- '--org-policy-sha256 abc123' '$TMP/docker.log'"
DEP_GUARD_ORG_POLICY="$TMP/missing.exs" run "$P" && code=0 || code=$?
check "a missing org policy file is an error" test "$code" = 2

# 5. base lock handling -------------------------------------------------------------------
P=$(new_project nobase)
(cd "$P" && git update-ref -d refs/remotes/origin/main)
run "$P" || true
check "no base branch: warn and skip the lock-change check" grep -q "lock-change check is skipped" "$TMP/stderr"
check "no base branch: no --base-lock is passed" sh -c "! grep -q -- '--base-lock' '$TMP/docker.log'"

P=$(new_project explicitbase)
(cd "$P" && echo '%{"x": {:hex, :x, "1.0.0", "c", [:mix], [], "hexpm", "o"}}' >mix.lock && git add . && git commit -q -m lock && git update-ref refs/remotes/origin/dev HEAD)
DEP_GUARD_BASE=origin/dev run "$P" || true
check "DEP_GUARD_BASE selects the base" grep -q -- "--base-lock /out/base.lock" "$TMP/docker.log"
check "the base lock is the content at that ref" grep -q ':hex, :x, "1.0.0"' "$P/.dep_guard/base.lock"

# 6. CI and cache behaviour -----------------------------------------------------------------
P=$(new_project ci)
GITHUB_ACTIONS=true GITHUB_REPOSITORY=acme/app GITHUB_SHA=abc123 GITHUB_REF_NAME=feature run "$P" || true
check "CI uses a tmpfs cache" grep -q -- "--tmpfs /cache" "$TMP/docker.log"
check "CI records the repo, commit and branch" \
  sh -c "grep -q 'DEP_GUARD_REPO=acme/app' '$TMP/docker.log' && grep -q 'DEP_GUARD_COMMIT=abc123' '$TMP/docker.log' && grep -q 'DEP_GUARD_BRANCH=feature' '$TMP/docker.log'"
P=$(new_project local)
run "$P" || true
check "a local run keeps a persistent cache" grep -q -- "$TMP/home/.cache/dep_guard:/cache/dep_guard" "$TMP/docker.log"

# 7. preconditions ----------------------------------------------------------------------------
mkdir -p "$TMP/empty"
run "$TMP/empty" && code=0 || code=$?
check "no mix.lock is a clear error" test "$code" = 2
check "no mix.lock says what to do" grep -q "no mix.lock" "$TMP/stderr"
check "--help works without docker" sh -c "PATH=/usr/bin:/bin sh '$SCRIPT' --help | grep -q 'Usage: dep-guard'"

echo
if [ "$FAILS" -gt 0 ]; then
  echo "$FAILS check(s) failed"
  exit 1
fi
echo "all checks passed"
