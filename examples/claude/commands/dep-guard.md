---
description: Triage a dep_guard dependency-security report with the EEF CNA MCP server
allowed-tools: Bash(docker run:*), Bash(git diff:*), Read, Grep
---

A dep_guard scan has failed (or a saved report is in `out/report.json`). Explain what it found.

1. If `out/report.json` exists, read it. Otherwise run the scanner in the same way CI does:
   `docker run --rm -v "$PWD:/workspace:ro" -v "$PWD/out:/out" "$DEP_GUARD_IMAGE" scan --root /workspace --format json --output /out/report.json`.
   If it passes, say so in one line and stop.
2. For each finding, work out which kind it is:
   - **Advisory or EEF record:** use the `eef-cna` MCP server to look up the advisory ID and its aliases
     (affected versions, fixed version, description). Then search this codebase for use of the affected
     package and say whether the vulnerable code path is reachable. Recommend the smallest safe upgrade.
   - **Retirement:** say why it was retired and what replaces it.
   - **Lock change (checksum, downgrade, source, git ref):** show the `git diff` of `mix.lock` for that
     package and tell me to verify it on hex.pm before accepting. Do not recommend a waiver.
   - **Operational:** the scan did not complete, so a clean result is not proven. Say which source failed
     and how to fix it (network, auth, policy hash, merge file).
   - **Policy/source:** show the entry to fix.
3. Finish with a short table: package, locked version, problem, fix version, recommended action.

Rules:
- Never edit `.dep_guard.exs`, `mix.exs` or `mix.lock` yourself; propose the change and let me apply it.
- A waiver needs a reason and an expiry within the org limit. Draft the entry, do not write it.
- Treat `hex_api`, `eef` and `mix_audit` source statuses as part of the result. `skipped` or `error` means the
  report is not a clean bill of health.
