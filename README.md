# dep_guard

An ExUnit suite that audits an Elixir project's dependencies, plus the tooling to triage failures. Add it
to every app so the whole company runs the same checks, with the same policy format, in `mix test`.

> **Status:** 53 unit tests pass (Elixir 1.18.4 / OTP 25). Verified in CI against the real services (OTP 27):
> `mix hex.audit` and `mix deps.audit` run in a subprocess and flag `sweet_xml 0.6.6` (GHSA-qpmc-wprv-x746), the EEF OSV
> feed per-record URL and record shape, and a clean project passes. See "Unverified" for what remains.

## What it checks

| Test | Network | Catches |
|---|---|---|
| Lockfile integrity | no | Missing checksums, git deps pinned to a branch rather than a commit, odd lock entries. `mix.lock` is parsed as data, never evaluated. |
| Allowed sources | no | A dependency moving to an unexpected Hex repo or git URL (dependency confusion). |
| Policy hygiene | no | Waivers with no reason or expiry, expired, too far out, or stale. |
| No bypass in `mix.exs` | no | `hex: [ignore_advisories: ...]` in `mix.exs`, which would skip expiry. |
| Lock changes vs base branch | git only | Same version with a different checksum, downgrades, source/repo/URL changes. New and removed packages are printed as notices. |
| `mix hex.audit` | yes | Retired packages and, on Hex 2.5+, security advisories. |
| `mix deps.audit` (mix_audit) | yes | Advisories from elixir-security-advisories. |
| EEF CNA OSV feed (on by default) | yes | Advisories published by the EEF, the CNA for the BEAM ecosystem. |

## EEF CNA integration

- **OSV feed (in the suite).** `https://cna.erlef.org/osv/all.json` is public. The suite fetches each record and matches
  it against your lock with the standard OSV range rules. It fails closed: unreachable feed, unreadable records or
  an unevaluable range all fail the test.
- **GraphQL API (`DepGuard.EefGraphQL`).** Token from the `EEF_CNA_TOKEN` environment variable (a CI secret), never logged.
  `published_cves/1` uses the query from the EEF's own example and returns `cveId` and `title` only, which is not
  enough to match against a lockfile. Run `mix dep_guard.eef schema` with a token to list the real fields, then
  extend the query and add a matching check.
- **MCP server (`examples/mcp.json`, `examples/claude/commands/dep-guard.md`).** Copy `mcp.json` to `.mcp.json` and the
  command to `.claude/commands/dep-guard.md`. When the suite fails, `/dep-guard` runs it, looks up each CVE on the
  `eef-cna` server, checks whether your code reaches the vulnerable path, and recommends the smallest safe fix. It never
  edits the policy, `mix.exs` or `mix.lock` itself. This is a triage aid, not a gate: CI decisions come from the
  deterministic checks above.

## Setup

1. Add to the app (as a git or private-Hex dependency):

   ```elixir
   {:dep_guard, "~> 0.1", only: :test, runtime: false},
   {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
   ```

2. Add `test/security/dependencies_test.exs` (see `examples/dependency_security_test.exs`).
3. Optionally add `.dep_guard.exs` (see `examples/.dep_guard.exs`). Without it the strictest policy applies.
4. Copy `examples/github/dependency-security.yml` to `.github/workflows/`. It runs on every PR and nightly, and opens an issue
   if the nightly run fails. The project needs a `.tool-versions` file.

```
mix test test/security                    # everything
mix test test/security --exclude online   # offline checks only
DEP_GUARD_BASE_REF=origin/main mix test test/security   # include the lock-change test
```

For an umbrella, run the suite from the umbrella root, or pass `root:` to `use DepGuard.Suite`.

## Design choices

- **Waivers expire.** Ignoring a finding needs a reason and a date. Expired waivers stop applying, so the finding returns.
- **No env bypass.** The suite sets `HEX_IGNORE_ADVISORIES` and `HEX_IGNORE_RETIREMENTS` itself (unsetting them when empty), so a CI variable cannot silence the audit.
- **Tamper signal.** A locked version whose checksum changes is the one change that should never happen silently, and neither audit tool checks it.
- **Fail closed.** Anything the suite cannot read or evaluate is a failure, not a pass.
- **Audits run as subprocesses.** `mix hex.audit` must run before the app loads, which a test process has already done. The suite reports each tool's output verbatim.

## Verified notes

- `cna.erlef.org/osv/<id>.json` returns HTTP 406 if the request carries `Accept: application/json`, so the HTTP client sends no `Accept` header.
- Hex records use `package.ecosystem: "Hex"`, SEMVER ranges and an explicit `versions` list. Each record also has a separate package-less `GIT` entry, which the matcher ignores.
- `mix hex.audit` on Hex 2.5+ reports advisories as well as retirements, so it overlaps with `mix deps.audit`.

## Unverified

- The `/mcp` endpoint and the GraphQL schema beyond `listPublishedCves { results { cveId title } }`.
- The HTTP client needs OTP 25+ and Elixir 1.18+ (built-in `JSON`), or the `:jason` package.

## Limits

- It finds *known* problems. A malicious release nobody has reported yet passes every advisory check; the lock-change test and review of `mix.lock` diffs are the defence.
- Advisory databases overlap but differ, which is why several are queried.
- `mix hex.audit` also exits non-zero on network errors, so read the output before assuming a vulnerability.
- Your own application code is out of scope (use `sobelow`).
