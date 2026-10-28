# Authoritative org policy. Keep one copy in a shared repo, review changes with
# CODEOWNERS, and pin the file's SHA-256 in the workflow (an org variable, not a
# value a pull request can edit).
#
# The project's .dep_guard.exs may only add waivers; it cannot change these.
%{
  schema_version: 1,

  # Waivers live in each project. Add org-wide waivers here only when they apply
  # to every project, and give each one a reason and an expiry.
  ignore_advisories: [],
  ignore_retirements: [],
  allow_downgrades: [],
  allow_git_refs: [],

  # Public Hex only. Add a private repo only if it is mirrored and audited.
  allowed_repos: ["hexpm"],

  # Git dependencies must be listed here with their exact URL. They are also
  # pinned to a full commit SHA in mix.lock by the integrity check.
  allowed_git: [],

  max_ignore_days: 90,
  require_outer_checksum: true
}
