%{
  # Every waiver needs a reason and an expiry (YYYY-MM-DD), at most max_ignore_days away.
  # Expired waivers stop applying, so the audit fails again, and the policy test fails too.
  ignore_advisories: [
    # %{
    #   id: "GHSA-xxxx-xxxx-xxxx",
    #   aliases: ["CVE-2026-0000"],        # every ID the tools might report
    #   package: "plug",
    #   reason: "Vulnerable code path is not reachable: we never call Plug.X",
    #   expires: "2026-12-01"
    # }
  ],
  ignore_retirements: [
    # %{package: "some_lib", version: "1.2.3", reason: "Replacement lands in ticket ABC-123", expires: "2026-11-30"}
  ],
  allow_downgrades: [
    # %{package: "plug", reason: "Rolling back a broken release, incident INC-42", expires: "2026-11-05"}
  ],

  # Hex repos the project may use ("hexpm" is the public registry).
  allowed_repos: ["hexpm"],

  # Git dependencies must be listed with their exact URL (and are pinned to a commit in mix.lock).
  allowed_git: [
    # %{app: "internal_lib", url: "https://github.com/acme/internal_lib.git"}
  ],

  max_ignore_days: 90,
  require_outer_checksum: true
}
