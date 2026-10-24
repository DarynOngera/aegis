---
description: Run the dependency-security suite and triage any failures with the EEF CNA MCP server
allowed-tools: Bash(mix test:*), Bash(git diff:*), Read, Grep
---

Run the dependency-security suite and explain what it found.

1. Run `mix test test/security`. If it passes, say so in one line and stop.
2. For each failure, work out which kind it is:
   - **Advisory or CVE hit:** use the `eef-cna` MCP server to look up the CVE (affected versions,
     fixed version, description). Then search this codebase for use of the affected package and say
     whether the vulnerable code path is reachable. Recommend the smallest safe upgrade, or a
     waiver in `.dep_guard.exs` only if the path is genuinely unreachable.
   - **Retired package:** say why it was retired and what replaces it.
   - **Lock change (checksum, downgrade, source):** show the `git diff` of `mix.lock` for that
     package and tell me to verify it on hex.pm before accepting. Do not recommend a waiver.
   - **Policy or source problem:** show the exact line to fix.
3. Finish with a short table: package, locked version, problem, fix version, recommended action.

Rules:
- Never edit `.dep_guard.exs`, `mix.exs` or `mix.lock` yourself; propose the change and let me apply it.
- A waiver needs a reason and an expiry within 90 days. Draft the entry, do not write it.
- If the MCP server is unreachable, say so and continue with the information in the test output.
