# dep_guard

A standalone dependency scanner for Elixir projects. It reads a project's `mix.lock` and `mix.exs` as data,
checks them against Hex and the EEF CNA advisory feed, and writes one report. It is packaged as a container
and is **not** added to the project's dependencies, so a project cannot skip it by changing `mix.exs`.

- One scan, one report: JSON is canonical; SARIF and human output are renderings.
- Every source records a status. `uncovered` or `error` makes the scan incomplete (exit 2); `skipped`
  does not prove coverage.
- Missing data or an unreachable source is an operational failure (exit 2), never a silent pass.
- The project may only waive findings; the org policy owns allowlists, limits and source requirements.
- `mix_audit` stays an external, project-owned check. Its JSON is merged when supplied.

## Quick start

```sh
# Scan the current project and print a human summary.
docker run --rm --read-only --tmpfs /cache \
  -v "$PWD:/workspace:ro" \
  ghcr.io/acme/dep_guard@sha256:<digest> \
  scan --root /workspace
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` operational error,
`3` reserved (not emitted today).

Write a canonical report and re-render it later without rescanning:

```sh
docker run --rm --read-only --tmpfs /cache \
  -v "$PWD:/workspace:ro" -v "$PWD/out:/out" \
  ghcr.io/acme/dep_guard@sha256:<digest> \
  scan --root /workspace --format json --output /out/report.json

docker run --rm -v "$PWD/out:/out" \
  ghcr.io/acme/dep_guard@sha256:<digest> \
  render --input /out/report.json --format sarif --output /out/report.sarif
```

## What it checks

| Check | Network | Catches |
|---|---|---|
| Lockfile integrity | no | Missing or malformed checksums, git deps not pinned to a full commit SHA, unknown lock entry formats. `mix.lock` is parsed as data, never evaluated. |
| Sources | no | A dependency moving to an unexpected Hex repo or git URL (dependency confusion). |
| Policy hygiene | no | Waivers without a reason or expiry, expired, too long, or stale; invalid allowlists. |
| `mix.exs` | no | `hex: [ignore_advisories: ...]` in `mix.exs`, which would bypass expiry. Computed values are reported, not guessed. |
| Lock changes | no | Same version with a different checksum, downgrade, source/repo change, git URL/ref change. New/removed packages are notices. |
| Hex API | yes | Retirements and security advisories, with CVSS severity. |
| EEF CNA OSV feed | yes | Advisories published by the EEF, the CNA for the BEAM ecosystem. |
| `mix_audit` (optional) | no | Merged from a JSON file the project produces. Not run by the scanner. |

## Docs

- [`USAGE.md`](USAGE.md): org rollout, policy layering, CI, image pinning, report schema, troubleshooting.
- [`examples/`](examples): org policy, project waivers, a GitHub Actions workflow, MCP triage command.

## Development

```sh
mix test
mix format --check-formatted
MIX_ENV=test mix compile --warnings-as-errors
mix escript.build            # local CLI, for development only
```

The container is the delivery format:

```sh
docker build -t dep_guard:dev .
docker run --rm dep_guard:dev version
```

Base images are pinned by tag and digest in the `Dockerfile`. The runtime image has no `git`; CI resolves
the base lock with `git show` and passes it as `--base-lock`. `--base-ref` is for local development only.

## Limits

- It finds *known* problems. An unreported malicious release passes the advisory checks; the lock-diff
  check and review of `mix.lock` changes are the defence.
- Your own application code is out of scope (use `sobelow`).
- Private Hex packages on a non-public repo are reported as `uncovered`: the public API cannot prove them clean.
