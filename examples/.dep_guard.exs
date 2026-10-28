# Project waivers. This file may contain only the four waiver lists below; the
# org policy owns allowlists, limits and source requirements.
#
# Every waiver needs a reason and an expiry (YYYY-MM-DD), at most
# `max_ignore_days` away. Expired waivers stop applying, and the policy check
# fails until the entry is renewed or deleted.
%{
  ignore_advisories: [
    # %{
    #   id: "GHSA-xxxx-xxxx-xxxx",
    #   aliases: ["CVE-2026-0000", "EEF-CVE-2026-0000"],
    #   package: "plug",
    #   reason: "Vulnerable path is not reachable: we never call Plug.X",
    #   expires: "2026-12-01"
    # }
  ],
  ignore_retirements: [
    # %{package: "some_lib", version: "1.2.3", reason: "Replacement in ABC-123", expires: "2026-11-30"}
  ],
  allow_downgrades: [
    # %{package: "plug", reason: "Rollback during INC-42", expires: "2026-11-05"}
  ],
  allow_git_refs: [
    # %{app: "internal_lib", reason: "Reviewed upstream commit", expires: "2026-11-30"}
  ]
}
