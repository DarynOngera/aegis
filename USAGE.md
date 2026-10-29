# dep_guard: how to use it

dep_guard reads your project's `mix.lock` and tells you whether any dependency has a known security
problem. It runs in a container, so there is nothing to add to your project and nothing to install
except Docker and one small script.

**The short version**

```sh
cd my_app        # the folder that contains mix.lock
dep-guard        # scan; prints PASS or FAIL
```

The rest of this page is every step, in order. Sections 1-4 are for developers. Sections 5-6 are for
whoever sets it up for the team or the company, once.

| I want to... | Go to |
|---|---|
| Scan my project right now | [1](#1-before-you-start), [2](#2-install-the-dep-guard-command), [3](#3-run-your-first-scan) |
| Understand a FAIL and fix it | [4](#4-a-scan-failed-what-now) |
| Add it to GitHub CI | [5](#5-add-it-to-github-ci) |
| Publish the scanner for my org | [6](#6-set-it-up-for-your-org-once) |
| Look up an option, variable or exit code | [8](#8-reference) |
| Something broke | [9](#9-troubleshooting) |

---

## 1. Before you start

You need three things.

1. **Docker, running.** Check: `docker version` prints a Client and a Server section.
   If it prints an error about connecting, start Docker Desktop (or the Docker service).
2. **An Elixir project with `mix.lock` committed.** Check: `ls mix.lock mix.exs` shows both files.
   If `mix.lock` is missing, run `mix deps.get` and commit it. dep_guard scans the lock, not your code.
3. **Access to the scanner image.** The image is `ghcr.io/darynongera/aegis`. If it is private, log in
   once with a GitHub personal access token that has the `read:packages` scope:

   ```sh
   echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
   ```

   If `docker pull ghcr.io/darynongera/aegis:latest` works, you are already set.

## 2. Install the `dep-guard` command

`dep-guard` is a single shell script. It starts the container with the right settings so you never type
a long `docker run` line. You need the [GitHub CLI](https://cli.github.com) (`gh auth login`) because the
repository is private.

```sh
mkdir -p ~/.local/bin
gh api repos/DarynOngera/aegis/contents/scripts/dep-guard \
  -H "Accept: application/vnd.github.raw" > ~/.local/bin/dep-guard
chmod +x ~/.local/bin/dep-guard
```

Make sure `~/.local/bin` is on your `PATH`:

```sh
dep-guard --help        # prints the help text. If "command not found", add this to ~/.bashrc or ~/.zshrc:
export PATH="$HOME/.local/bin:$PATH"
```

To pin a released version of the script, add `-f ref=v0.2.0` to the `gh api` command.

## 3. Run your first scan

```sh
cd my_app
dep-guard
```

The first run downloads the image, so it takes a minute. After that a scan takes a few seconds.
You will see something like this.

**A scan that found a problem:**

```
dep_guard 0.2.0 — /workspace
sources:
  hex_api: ok (cached=0, duration_ms=310, packages=1, requests=1, uncovered=0)
  eef: ok (cached=0, duration_ms=3650, errors=0, fetched=349, records=349)
  mix_audit: not_included
findings:
  HIGH  sweet_xml 0.6.6  GHSA-qpmc-wprv-x746
    sweet_xml 0.6.6 is affected by GHSA-qpmc-wprv-x746: Inline DTD allows XML bomb attack
    fix: upgrade sweet_xml outside < 0.7.0
    sources: hex_api
FAIL — unwaived findings at or above high. (1 high, 0 medium, 0 low, 0 waived, 0 notices)
```

**A clean scan:**

```
sources:
  hex_api: ok (...)
  eef: ok (...)
PASS — no unwaived findings at or above high. (0 high, 0 medium, 0 low, 0 waived, 0 notices)
```

How to read it:

- `sources:` shows which advisory databases were asked. Both `hex_api` and `eef` should say `ok`.
  Anything else (`error`, `uncovered`, `skipped`) means the scan is **incomplete**, even if no findings
  are listed. Do not treat that as clean. Section 9 explains each one.
- `findings:` lists each problem: severity, package, version, the advisory ID, what it means, and the fix.
- The last line is the verdict.

The exit code is the same verdict for scripts and CI:

| Exit code | Meaning |
|---|---|
| `0` | PASS. Nothing at or above the threshold, and every source was checked. |
| `1` | FAIL. There are findings to fix or waive. |
| `2` | INCOMPLETE or error. The scan could not finish (no network, bad policy file, unreachable advisory source). Fix the cause and run again. |

Where the files go: `dep-guard` writes `report.json` and `report.sarif` to a `.dep_guard/` folder in your
project. It adds its own `.gitignore` inside that folder, so you do not need to edit yours.

**It also checks what changed.** If your branch changes `mix.lock`, dep_guard compares it with
`origin/main` (or `origin/master`) and flags things a human should look at: a checksum that changed
without a version change (possible tampering), a downgrade, or a dependency moving to a different
source. To compare with another branch: `DEP_GUARD_BASE=origin/develop dep-guard`. If there is no base
branch (for example a fresh clone with no `origin/main`), it says so and skips only this part.

## 4. A scan failed. What now?

Take the findings one at a time. For each one, do the first option that applies.

### a) Upgrade the dependency (almost always the right answer)

The `fix:` line says what to upgrade to.

```sh
mix deps.update sweet_xml
git add mix.lock
dep-guard
```

If the update is blocked by a version requirement in `mix.exs`, loosen it (for example `"~> 0.6.0"`
to `"~> 0.7"`), run `mix deps.update sweet_xml` again, then scan.

### b) Waive it, temporarily and on the record

Use this only when you cannot upgrade yet or the vulnerable code is not reachable. Create or edit
`.dep_guard.exs` in the project root:

```elixir
%{
  ignore_advisories: [
    %{
      id: "GHSA-qpmc-wprv-x746",
      aliases: ["CVE-2019-15160"],
      package: "sweet_xml",
      reason: "We never parse XML from outside our network. Upgrade tracked in ABC-123.",
      expires: "2026-12-01"
    }
  ]
}
```

Rules, all enforced by the scanner:

- `reason` and `expires` (`YYYY-MM-DD`) are required.
- `expires` cannot be more than 90 days away (the org can change that limit).
- An expired waiver stops working **and** is reported as its own finding, so waivers cannot quietly
  become permanent.
- A waiver for a package that is no longer in `mix.lock` is reported until you delete it.
- Waived findings are still shown in the report, marked as waived.

The other waiver lists in the same file:

| List | Use it for | Required keys |
|---|---|---|
| `ignore_advisories` | A known advisory you accept for now | `id`, `package`, `reason`, `expires` |
| `ignore_retirements` | A package its maintainer retired | `package`, `reason`, `expires` |
| `allow_downgrades` | A deliberate move to an older version | `package`, `reason`, `expires` |
| `allow_git_refs` | A deliberate change of a git dependency's commit | `app`, `reason`, `expires` |

Each waiver applies only to the package or app it names. There is no wildcard.

### c) Things you cannot waive

- **A checksum changed but the version did not.** Treat this as possible tampering. Check the package
  on hex.pm, then run `mix deps.get` fresh. There is deliberately no waiver for it.
- **Missing checksum, git dependency not pinned to a commit, dependency from an unapproved source.**
  Fix the lock or ask whoever owns the org policy.
- **Exit code 2.** Not a finding. The scan did not complete. Section 9.

Run `dep-guard` again after each change until it says PASS.

---

## 5. Add it to GitHub CI

Do this once per project. It scans every pull request, and also every night, so a newly published
advisory turns the build red even if nobody pushed.

1. Create `.github/workflows/dependency-security.yml` in your project with this content
   (also in [`examples/github/dependency-security.yml`](examples/github/dependency-security.yml)):

   ```yaml
   name: dependency-security

   on:
     pull_request:
     schedule:
       - cron: "17 3 * * *"
     workflow_dispatch:

   permissions:
     contents: read

   jobs:
     scan:
       runs-on: ubuntu-latest
       timeout-minutes: 20
       steps:
         - uses: actions/checkout@v4
         - uses: DarynOngera/aegis@v0.2.0
           with:
             image: ghcr.io/darynongera/aegis@sha256:<digest>
   ```

   Replace `<digest>` with the image digest (section 6, step 1). A digest pins the exact image; a tag like
   `:latest` can change under you.
2. If your project's `mix.lock` is in a subfolder, add `working-directory: apps/web` under `with:`.
3. Commit, push, and open a pull request. The **dependency-security / scan** check appears on the PR.
   Open it to read the same summary you saw locally.
4. To make it block merging: repository **Settings, Branches**, edit the branch protection rule, tick
   **Require status checks to pass**, and select `scan`.

You do not need `fetch-depth: 0`. On pull requests the action fetches the base branch itself for the lock-change check.
The nightly run has no base branch, so only that one check is skipped; the advisory checks all run.

If the action lives in a private repository, allow other repositories to use it:
`DarynOngera/aegis` **Settings, Actions, General, Access**, then choose the option that allows
repositories in your organization (or user account).

Options you can set under `with:`:

| Input | Default | What it does |
|---|---|---|
| `image` | `ghcr.io/darynongera/aegis:latest` | The scanner image. Pin a digest. |
| `working-directory` | `.` | Folder holding `mix.lock` and `mix.exs`. |
| `fail-on` | `high` | Lowest severity that fails the job: `any`, `low`, `medium`, `high`, `critical`. |
| `org-policy` | none | Path to the org policy file (section 6, step 3). |
| `org-policy-sha256` | none | Expected hash of that file. |
| `upload-sarif` | `false` | Send results to GitHub code scanning. Needs `security-events: write`, and Advanced Security on private repositories. |
| `artifact-name` | `dep_guard-report` | Name of the saved report. Use a different name for each call in one job. |

The saved `report.json` and `report.sarif` are attached to the workflow run as an artifact.

### Optional: scan before you push

A git hook that runs `dep-guard` only when `mix.lock` changed, so normal pushes stay instant:

```sh
gh api repos/DarynOngera/aegis/contents/examples/hooks/pre-push \
  -H "Accept: application/vnd.github.raw" > .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

Skip it once with `git push --no-verify`. CI still checks.

### Optional: `mix security`

To run it with a mix command, add one line to your `mix.exs`:

```elixir
def project do
  [
    # ...
    aliases: [security: "cmd dep-guard"]
  ]
end
```

Then `mix security` runs the scan.

---

## 6. Set it up for your org (once)

Only the person who owns the scanner and the org policy does this.

### Step 1: publish the scanner image

1. In the `aegis` repository, make sure `@version` in `mix.exs` is the version you want (for example `0.2.0`).
2. Push a matching tag:

   ```sh
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. The **release** workflow builds the image and pushes it to `ghcr.io/darynongera/aegis`. If the tag and
   `@version` differ, it stops with an error.
4. Open the finished workflow run. The summary shows the image digest, like
   `ghcr.io/darynongera/aegis@sha256:...`. This is the value to give to every project.
5. Let your other repositories pull it: on GitHub open the package (your profile or org, **Packages**,
   `aegis`), **Package settings**, **Manage Actions access**, and add the repositories (or the org).

This workflow has not yet been run for the first time. If a step fails, the error message in the run says which.

### Step 2: decide the rules (the org policy)

Copy [`examples/org.dep_guard.exs`](examples/org.dep_guard.exs). It controls what projects cannot change:
which Hex repos are allowed, which git dependencies are allowed, the longest a waiver may last, and
whether an outer checksum is required. Keep one copy in a shared repository, protected by CODEOWNERS.

A project's `.dep_guard.exs` can only add waivers. It cannot widen anything here.

### Step 3: pin the policy so a pull request cannot change it

1. Compute the hash: `sha256sum org.dep_guard.exs`
2. Save it as an **organization-level variable**: GitHub **Settings, Secrets and variables, Actions,
   Variables**, name `DEP_GUARD_ORG_POLICY_SHA256`. It must be a variable a project's pull request cannot
   edit. A hash stored in the same pull request as the file proves nothing.
3. Each project checks out the shared repository and passes both values:

   ```yaml
   steps:
     - uses: actions/checkout@v4
     - uses: actions/checkout@v4
       with:
         repository: acme/security-policy
         ref: <commit sha>
         path: .org-policy
     - uses: DarynOngera/aegis@v0.2.0
       with:
         image: ghcr.io/darynongera/aegis@sha256:<digest>
         org-policy: .org-policy/org.dep_guard.exs
         org-policy-sha256: ${{ vars.DEP_GUARD_ORG_POLICY_SHA256 }}
   ```

   If the file changes without the variable changing, the scan stops with exit code 2 and says the hash
   does not match. When you change the policy on purpose, update the variable at the same time.

For local runs: `DEP_GUARD_ORG_POLICY=/path/to/org.dep_guard.exs DEP_GUARD_ORG_POLICY_SHA256=... dep-guard`.

### Step 4: pin third-party actions

In your own repositories, pin `actions/checkout`, `DarynOngera/aegis` and the others to full commit SHAs
rather than tags. The examples use tags only to stay readable.

---

## 7. What it checks

| Check | Needs network | What it catches |
|---|---|---|
| Lockfile | no | Missing or malformed checksums. Git dependencies not pinned to a full commit SHA. Unknown lock formats. |
| Sources | no | A dependency from a Hex repo or git URL the org policy does not allow. |
| Policy | no | Waivers that are incomplete, expired, too long, or stale. |
| `mix.exs` | no | A literal `hex: [ignore_advisories: ...]` in `mix.exs`, which would skip waiver expiry. |
| Lock changes | no (needs a base branch) | Same version with a new checksum, removed checksum, downgrade, source or repo change, git URL or commit change. New and removed packages are shown as notices. |
| Hex API | yes | Retired packages and security advisories, with severity from the CVSS rating. |
| EEF CNA feed | yes | Advisories published by the Erlang Ecosystem Foundation, the CVE Numbering Authority (CNA) for the BEAM ecosystem. |
| `mix_audit` | no | Optional. Merges the JSON from `mix deps.audit --format json` if you pass `--mix-audit-report /workspace/<file>`. |

Findings for the same advisory that arrive from several sources are merged into one, matched by advisory ID
or alias. The highest severity wins.

---

## 8. Reference

### `dep-guard` options

Everything after `dep-guard` is passed to the scanner. The ones you will use:

| Option | Meaning |
|---|---|
| `--fail-on LEVEL` | `any`, `low`, `medium`, `high` (default), `critical`. Lowest severity that gives exit 1. |
| `--offline` | Skip the Hex API and EEF checks. The scan then exits 2, because nothing about advisories was checked. |
| `--allow-skipped` | With `--offline`: accept the skipped sources and exit 0 if nothing else is wrong. The report records that you did. Do not use this in CI. |
| `--policy FILE` | Project waivers (default `.dep_guard.exs`). A path you pass must be as the container sees it: your project is `/workspace`. |

Do not pass `--format` or `--output`. The command always writes JSON, SARIF and a summary itself.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DEP_GUARD_IMAGE` | `ghcr.io/darynongera/aegis:latest` | Image to run. In CI use `name@sha256:<digest>`. |
| `DEP_GUARD_BASE` | PR base branch in CI; else `origin/main` or `origin/master` | Git ref to compare `mix.lock` with. |
| `DEP_GUARD_ORG_POLICY` | none | Path to the org policy file. |
| `DEP_GUARD_ORG_POLICY_SHA256` | none | Expected SHA-256 of that file. |
| `DEP_GUARD_ROOT` | current directory | Project directory. |
| `DEP_GUARD_OUT` | `<project>/.dep_guard` | Where the reports go. |
| `DEP_GUARD_NO_CACHE` | unset | `1` skips the persistent HTTP cache. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No unwaived findings at or above `--fail-on`, and every source was checked. |
| `1` | One or more unwaived findings at or above `--fail-on`. |
| `2` | The scan did not finish: bad input, missing lock, policy hash mismatch, a source that errored, was unreachable, could not cover a package, or was skipped. If a vulnerability and an incomplete source both exist, you still get `2`, because the report is incomplete. |
| `3` | Reserved. Not used today. |

### What each source status means

| Status | Meaning | Exit |
|---|---|---|
| `ok` | Asked for every package and answered. | |
| `error` | Could not be asked completely (network, timeout, malformed answer). | 2 |
| `uncovered` | A package on a private Hex repo, or one the public API does not know. It cannot be proven clean. | 2 |
| `skipped` | Deliberately not run (`--offline`). | 2, unless `--allow-skipped` |
| `merged` | An external `mix_audit` report was merged. | |
| `not_included` | No `mix_audit` report was given. | |

### The report

`report.json` is the one complete result. The SARIF file and the terminal summary are views of it. It records the
scanner version and image digest, project, repo (credentials stripped), commit and branch, the SHA-256 of
`mix.lock` and of the policy files, the date used to judge waivers (`inputs.evaluated_on`), each source's
status, all findings (including waived ones) and a summary.

Re-render a saved report without scanning (no network): run the container with
`render --input /out/report.json --format sarif|human|json`. `render` always exits 0 when it writes; the
verdict is in the report, not in `render`'s exit code.

### Without the wrapper

The command `dep-guard` runs, in effect:

```sh
docker run --rm --read-only --tmpfs /cache \
  -v "$PWD:/workspace:ro" -v "$PWD/.dep_guard:/out" \
  ghcr.io/darynongera/aegis:latest \
  scan --root /workspace --format json --output /out/report.json
```

The runtime has no `git`, so the wrapper reads the base `mix.lock` with `git show` and passes it as `--base-lock`.

---

## 9. Troubleshooting

| What you see | What it means and what to do |
|---|---|
| `dep-guard: command not found` | `~/.local/bin` is not on your `PATH`. See section 2. |
| `dep-guard: docker is required` | Docker is not installed or its CLI is not on `PATH`. |
| `failed to connect to the docker API` | Docker is installed but not running. Start it. |
| `pull access denied` or `unauthorized` | You are not logged in to `ghcr.io`, or the token lacks `read:packages`. Section 1, step 3. |
| `dep-guard: no mix.lock in ...` | You are not in the project root. `cd` to the folder with `mix.lock`, or set `DEP_GUARD_ROOT`. |
| `no base branch found, so the lock-change check is skipped` | There is no `origin/main` or `origin/master` locally. Run `git fetch origin main`, or set `DEP_GUARD_BASE`. Everything else is still checked. |
| Exit `2` and `eef: ... could not be fetched` | The EEF feed was unreachable or answered with errors. The scan fails closed on purpose. Check your network and run again. |
| Exit `2` and `HTTP 429` | A source rate-limited the request. Wait a minute and run again. |
| Exit `2`, `hex_api: ... private Hex repo` or status `uncovered` | The public advisory API cannot check a private package. Mirror and audit it, or accept that it is unchecked. |
| Exit `2`, `SHA-256 ... but the pinned value is ...` | The org policy file does not match the pinned hash. Review the change, then update the variable. |
| Exit `2` after `--offline` | By design: nothing about advisories was checked. Drop `--offline`. |
| `--today overrides the date ... for tests only` | The `--today` option is only for tests. It is refused unless `DEP_GUARD_ALLOW_TODAY=1`, and the report records that it was used. |
| `lockfile` finding on an old lock | Run `mix deps.get`. An old lock without an outer checksum can be allowed only by the org policy (`require_outer_checksum: false`). |
| `ignore_advisories ... expired on ...` | A waiver ran out. Upgrade the dependency, or renew the waiver after a fresh review. |
| Reports are not in git status | Correct. `.dep_guard/` ignores itself. |

## 10. Limits

- It finds **known** problems. A malicious release nobody has reported passes the advisory checks. The lock-change
  check and reviewing `mix.lock` diffs are the defence against that.
- Hex and EEF overlap but are not identical, which is why both are queried.
- Private Hex packages show as `uncovered`.
- Your own application code is out of scope. Use `sobelow`.
- Each scan fetches the EEF index and every record (hundreds, and growing), and one request per package from Hex.
  The cache lives for one hour, but CI containers start empty. On a busy org, expect to need a shared cache or
  a mirror if you see rate-limit errors.

## 11. Working on dep_guard itself

```sh
mix test                                       # unit tests, offline
sh test/scripts/dep_guard_wrapper_test.sh      # the dep-guard command, against a fake docker
sh test/scripts/pre_push_hook_test.sh          # the pre-push hook
mix format --check-formatted
MIX_ENV=test mix compile --warnings-as-errors
mix escript.build                              # local CLI for development: ./dep_guard scan --root . --offline --allow-skipped
docker build -t dep_guard:dev . && docker run --rm dep_guard:dev version
```

Needs Elixir 1.18+ and OTP 25+ (the built-in `JSON` module and `:public_key.cacerts_get/0`).
CI builds the real image, scans the fixtures in `integration/` against live Hex and EEF, and runs the
GitHub Action end to end.
