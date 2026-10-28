# dep_guard: usage

`dep_guard` is a standalone scanner. It is delivered as a container image, reads a project's `mix.lock`,
`mix.exs` and policy files, and writes one report. It is never added to a project's dependencies, so a
project cannot skip the gate by editing its `mix.exs`.

## 1. Run a scan

```sh
docker run --rm --read-only --tmpfs /cache \
  -v "$PWD:/workspace:ro" \
  ghcr.io/acme/dep_guard@sha256:<digest> \
  scan --root /workspace
```

`scan` options:

| Option | Meaning |
|---|---|
| `--root DIR` | Project root holding `mix.lock` and `mix.exs` (default: `.`). |
| `--org-policy FILE` | Authoritative org policy. Without it, the strict default applies. |
| `--org-policy-sha256 SHA` | Expected SHA-256 of the org policy. A mismatch is an operational error. |
| `--policy FILE` | Project waivers (default: `DIR/.dep_guard.exs`). |
| `--base-lock FILE` | Compare `mix.lock` with a saved base lock. Use this in the container. |
| `--base-ref REF` | Compare with `git show REF:mix.lock` (needs `git`; local development only). |
| `--mix-audit-report FILE` | Merge `mix deps.audit --format json` output. |
| `--format human\|json\|sarif` | Output format (default `human`). |
| `--output FILE` | Write the report to a file instead of stdout. |
| `--fail-on any\|low\|medium\|high\|critical` | Gate threshold (default `high`). |
| `--offline` | Skip the online sources; cached data is not used. The report says advisory coverage is unproven. |
| `--cache-dir DIR` | HTTP cache (default `~/.cache/dep_guard`; the image uses `/cache/dep_guard`). |
| `--today YYYY-MM-DD` | Evaluation date for waiver expiry (tests/replays). |

The runtime image has no shell tooling beyond what ERTS needs and no `git`. Resolve the base lock in CI
with `git show` and pass it as `--base-lock`:

```sh
git show "origin/main:mix.lock" > out/base.lock
```

## 2. Policy: org layer and project layer

There are two files with different powers.

**Org policy** (`examples/org.dep_guard.exs`) is the complete policy: allowlists, waiver limits, source
requirements. Keep one copy in a shared repo, review it with CODEOWNERS, and pin its SHA-256 in CI:

```sh
sha256sum org.dep_guard.exs   # store this as an org-level CI variable
```

The hash must be a CI variable (or workflow constant) that a pull request cannot edit. Pinning both the
file and its hash inside the same PR proves nothing.

**Project policy** (`examples/.dep_guard.exs`, default `DIR/.dep_guard.exs`) may contain only the four
waiver lists:

- `ignore_advisories`
- `ignore_retirements`
- `allow_downgrades`
- `allow_git_refs`

Any other key is rejected, so a project cannot widen `allowed_repos`, add an `allowed_git` URL, raise
`max_ignore_days`, or turn off `require_outer_checksum`. Without the file, there are no project waivers.

Every waiver needs a `reason` and an `expires` date (`YYYY-MM-DD`) no further away than
`max_ignore_days`. Expired waivers stop applying and also fail the policy check. A waiver for a package
that has left `mix.lock` fails the policy check until it is deleted.

Both files are parsed as plain data. Function calls, interpolations and sigils are rejected before
evaluation, so a hostile policy change cannot run code inside the scanner.

## 3. What each check does

| Check | Kind | Gates? | Notes |
|---|---|---|---|
| `lockfile` | integrity | yes | Every Hex entry needs a 64-character checksum; `require_outer_checksum` also needs the outer value. Git entries need a full 40-character commit SHA. |
| `sources` | policy | yes | Hex entries must use an `allowed_repos` repo. Git entries must match an `allowed_git` app+URL pair. |
| `policy` | policy | yes | Waiver hygiene and allowlist shape. Expired or stale waivers block at the default threshold. |
| `mix_exs` | policy | yes | Literal `hex: [ignore_advisories: ...]` is a finding. A computed `hex:` value is reported as "cannot be inspected", never assumed empty. |
| `lock_changes` | integrity | yes | Checksum changed under the same version, checksum removed, downgrade, source/repo change, git URL/ref change. New/removed packages are notices. |
| `retirements` | security | yes | From the Hex API. Severity `high`. |
| `advisories` | security | yes | From the Hex API, with `cvss_rating` or `cvss_score` converted to a severity. |
| `eef` | security | yes | From the EEF CNA OSV feed. Severity `high` unless the record provides one. |
| `mix_audit` | security | yes | Only when `--mix-audit-report` is supplied. |
| `sources` notice | notice | no | Emitted when `--offline` skips online sources. |

An advisory whose severity cannot be read is treated as `high` for gating. Advisory findings for the same
package and version that arrive from several sources are merged by any shared ID or alias: the highest
severity wins, and the source list is unioned. One advisory affecting two different packages stays two
findings, because each is a separate upgrade.

## 4. One report

`scan` builds one `DepGuard.Report` and every output is a projection of it.

- **JSON** is canonical. It contains `schema_version`, `tool`, `run`, `project`, `policy`, `inputs`,
  `sources`, `findings`, `notices` and `summary`.
- **SARIF 2.1.0** is for code scanning. Source coverage and policy hashes are carried in run properties.
- **Human** output is for terminals and logs.

`render` reads a saved JSON report and re-renders it without a scan or network access:

```sh
docker run --rm -v "$PWD/out:/out" IMAGE \
  render --input /out/report.json --format sarif --output /out/report.sarif
```

Source statuses are part of the result:

| Status | Meaning |
|---|---|
| `ok` | The source was queried for every applicable package and found nothing (or its findings are in the report). |
| `error` | The source could not be queried completely. The report is incomplete; exit `2`. |
| `uncovered` | A private Hex repo or unknown package. The public API cannot prove it clean; exit `2`. |
| `skipped` | Deliberately not run (for example `--offline`). Not proof of cleanliness. |
| `merged` | An external `mix_audit` report was merged. |
| `not_included` | `mix_audit` JSON was not supplied. Never reported as `ok`. |

## 5. Exit codes

| Code | Meaning |
|---|---|
| `0` | No unwaived findings at or above `--fail-on`, and every required source completed. |
| `1` | One or more unwaived findings at or above `--fail-on`. |
| `2` | Operational failure: bad input, missing lock, policy hash mismatch, unreachable/partial source, bad merge file. |
| `3` | Reserved for an unsupported environment. Not emitted today. |

Operational findings always win: a scan with both a vulnerability and an unreachable advisory source exits
`2`, because the report is incomplete.

`render` exits `0` when it successfully writes a projection. It does not re-run the gate; the human
summary still uses the `--fail-on` threshold stored in the report, so a saved failing report renders as
`FAIL` without changing the renderer's exit code.

## 6. `mix_audit`

`mix_audit` remains the project's own check and is not bundled in the scanner image. When the project
produces its JSON, merge it into the same report:

```sh
mix deps.audit --format json > out/mix-audit.json || true   # exits non-zero on findings
docker run ... IMAGE scan --root /workspace --mix-audit-report /out/mix-audit.json
```

If the file cannot be read or does not have the expected `vulnerabilities` list, the scanner exits `2`
rather than producing a half-merged report. Findings for the same package and version are deduplicated
against Hex and EEF by advisory ID and alias.

## 7. CI

Copy `examples/github/dependency-security.yml` as a starting point. It:

- pins the scanner image by digest;
- checks out with full history and resolves `origin/<base>:mix.lock` into a file;
- mounts the workspace read-only and the report directory writable;
- passes the org policy and its SHA-256;
- records the repo, commit and branch in the report through `DEP_GUARD_REPO`,
  `DEP_GUARD_COMMIT` and `DEP_GUARD_BRANCH` (the image has no `git`);
- runs with a read-only root filesystem and a tmpfs cache;
- re-renders SARIF from the saved JSON and uploads it to code scanning (enable code scanning in the repo);
- keeps `report.json` as an artifact.

Third-party actions must be pinned to commit SHAs in your own repository. The example uses tags for
readability.

## 8. Build and publish the image

```sh
docker build -t dep_guard:0.2.0 .
docker run --rm dep_guard:0.2.0 version
```

The `Dockerfile` pins both base images by tag and digest. After pushing, read the registry digest and use
`image@sha256:...` in CI and deployment:

```sh
docker push ghcr.io/acme/dep_guard:0.2.0
docker image inspect --format '{{index .RepoDigests 0}}' ghcr.io/acme/dep_guard:0.2.0
```

Set `DEP_GUARD_IMAGE_DIGEST` when running the image to record it in `tool.image_digest`:

```sh
docker run -e DEP_GUARD_IMAGE_DIGEST="sha256:..." ... IMAGE scan ...
```

The runtime is a non-root user (uid 10001), has no `git`, and works with `--read-only`. The cache lives at
`/cache/dep_guard` (a tmpfs or volume). If `/cache` is not writable, caching is skipped and the scan still runs.

## 9. Offline and caching

Each HTTP response is cached by URL for one hour. The EEF feed is one record per advisory; a cold scan
takes roughly 10-30 seconds, a warm scan under 200 ms.

`--offline` skips both online sources rather than serving them from the cache, so an old cached
advisory cannot be mistaken for a fresh check. It does not pretend the project is clean: the report
includes a notice and the human output says the scan does not prove advisory coverage.

## 10. Development

```sh
mix test
mix format --check-formatted
MIX_ENV=test mix compile --warnings-as-errors
mix escript.build                    # local-only CLI
./dep_guard scan --root . --offline
```

The escript is for development. It is not the supported delivery path. `dep_guard` needs Elixir 1.18+ /
OTP 25+ because it uses the built-in `JSON` module and `:public_key.cacerts_get/0`.

## 11. Troubleshooting

| Symptom | Cause |
|---|---|
| `exit 2`, `HTTP 400` from hex.pm | A proxy stripped the `User-Agent`. The client always sets one. |
| `exit 2`, `SHA-256 ... but the pinned value is ...` | The org policy changed without updating its pinned hash, or the pin is stale. Review both. |
| `hex_api: uncovered` | A private Hex repo. Mirror and audit it, or accept that the public API cannot cover it. |
| `eef: ... could not be fetched` | The feed was unreachable or a record was malformed. The scan fails closed on purpose. |
| `lockfile` finding for an old lock | Run `mix deps.get`, or fix the entry by hand. An old lock without an outer checksum needs `require_outer_checksum: false` in the org policy. |
| Human output says `INCOMPLETE` | An operational finding exists. Do not treat the run as clean. |

## 12. Limits

- Known problems only. A malicious release nobody has reported passes the advisory checks; the lock-diff
  check and review of `mix.lock` changes are the defence.
- Advisory databases overlap but differ, which is why Hex and EEF are both queried.
- Private Hex packages are `uncovered`; the public API cannot see them.
- Your own application code is out of scope (use `sobelow`).
