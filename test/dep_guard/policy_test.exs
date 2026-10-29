defmodule DepGuard.PolicyTest do
  use ExUnit.Case, async: true

  alias DepGuard.{Finding, Policy}

  @today ~D[2026-10-24]
  @packages %{"plug" => "1.16.0", "jason" => "1.4.4"}

  defp waiver(attrs) do
    Map.merge(
      %{id: "CVE-2026-0001", package: "plug", reason: "not reachable", expires: "2026-12-01"},
      attrs
    )
  end

  defp problems(policy_attrs), do: Policy.problems(struct(Policy, policy_attrs), @packages, @today)

  defp tmp_file(contents) do
    path = Path.join(System.tmp_dir!(), "dep_guard_policy_#{System.unique_integer([:positive])}.exs")
    File.write!(path, contents)
    path
  end

  test "loading a missing file gives the strict default policy" do
    assert {:ok, %Policy{ignore_advisories: [], allowed_repos: ["hexpm"], require_outer_checksum: true}} =
             Policy.load("/nonexistent/.dep_guard.exs")
  end

  test "loading rejects unknown keys (typos must not weaken the policy)" do
    path = tmp_file("%{ignore_advisory: []}")
    on_exit(fn -> File.rm(path) end)

    assert {:error, message} = Policy.load(path)
    assert message =~ "unknown keys"
  end

  test "loading rejects a wrongly typed field instead of crashing" do
    assert {:error, message} = Policy.validate(%{allowed_repos: "hexpm"}, "org.exs")
    assert message =~ "allowed_repos has the wrong type"

    assert {:error, message} = Policy.validate(%{require_outer_checksum: "yes"}, "org.exs")
    assert message =~ "require_outer_checksum has the wrong type"

    assert {:error, message} = Policy.validate(%{schema_version: 2}, "org.exs")
    assert message =~ "schema_version must be 1"

    assert {:error, message} = Policy.validate(%{allowed_repos: nil}, "org.exs")
    assert message =~ "allowed_repos must not be nil"
  end

  test "a well-formed waiver has no problems" do
    assert problems(ignore_advisories: [waiver(%{})]) == []
  end

  test "missing reason or expiry is a problem" do
    assert [message] = problems(ignore_advisories: [waiver(%{reason: ""})])
    assert message =~ "missing :reason"

    assert [message] = problems(ignore_advisories: [waiver(%{expires: nil})])
    assert message =~ "missing :expires"
  end

  test "expired and too-distant waivers are problems" do
    assert [message] = problems(ignore_advisories: [waiver(%{expires: "2026-10-01"})])
    assert message =~ "expired on 2026-10-01"

    assert [message] = problems(ignore_advisories: [waiver(%{expires: "2027-12-31"})])
    assert message =~ "more than 90 days"

    assert [message] = problems(ignore_advisories: [waiver(%{expires: "soon"})])
    assert message =~ "not an ISO 8601 date"
  end

  test "waiver expiring today is still valid" do
    assert problems(ignore_advisories: [waiver(%{expires: "2026-10-24"})]) == []
  end

  test "stale waivers are problems" do
    assert [message] = problems(ignore_advisories: [waiver(%{package: "gone"})])
    assert message =~ "no longer in mix.lock"

    assert [message] =
             problems(ignore_retirements: [%{package: "plug", version: "1.0.0", reason: "r", expires: "2026-12-01"}])

    assert message =~ "pinned to 1.0.0 but mix.lock has 1.16.0"
  end

  test "malformed lists are reported, not crashed on" do
    assert [_] = problems(ignore_advisories: ["CVE-1"])
    assert [_] = problems(allowed_git: [%{app: "x"}])
    assert [_] = problems(allowed_repos: [:hexpm])
  end

  test "project overlay can add waivers but cannot weaken allowlists" do
    path = tmp_file(~s|%{allowed_repos: ["hexpm:evil"]}|)
    on_exit(fn -> File.rm(path) end)

    assert {:error, message} = Policy.validate_project(%{allowed_repos: ["hexpm:evil"]}, path)
    assert message =~ "unknown keys"

    assert {:ok, overlay, _sha} =
             Policy.validate_project(%{ignore_advisories: [waiver(%{})]}, path)

    assert overlay.ignore_advisories == [waiver(%{})]
  end

  test "layered policy merges waivers and records hashes" do
    org = tmp_file(~s|%{allowed_repos: ["hexpm"], max_ignore_days: 30}|)
    project = tmp_file(~s|%{ignore_retirements: [%{package: "plug", reason: "r", expires: "2026-12-01"}]}|)
    on_exit(fn -> File.rm(org) end)
    on_exit(fn -> File.rm(project) end)

    assert {:ok, %{policy: policy, hashes: hashes}} =
             Policy.load_layered(org: org, project: project)

    assert policy.allowed_repos == ["hexpm"]
    assert policy.max_ignore_days == 30
    assert [%{package: "plug"}] = policy.ignore_retirements
    assert is_binary(hashes.org_sha256)
    assert is_binary(hashes.project_sha256)
  end

  test "org policy hash mismatch is an error" do
    org = tmp_file(~s|%{allowed_repos: ["hexpm"]}|)
    on_exit(fn -> File.rm(org) end)

    assert {:error, message} =
             Policy.load_layered(org: org, org_sha256: String.duplicate("0", 64))

    assert message =~ "SHA-256"
  end

  test "an advisory waiver without a package is a policy problem and waives nothing" do
    no_package = Map.delete(waiver(%{id: "GHSA-1"}), :package)

    assert [message] = problems(ignore_advisories: [no_package])
    assert message =~ "missing :package"

    finding =
      Finding.new(id: "GHSA-1", check: :advisories, kind: :security, severity: :high, package: "plug", message: "x")

    refute Policy.waive(%Policy{ignore_advisories: [no_package]}, finding, @today).waived
  end

  test "advisory waivers are scoped to their package" do
    policy = %Policy{ignore_advisories: [waiver(%{package: "plug", id: "GHSA-1"})]}

    finding_plug =
      Finding.new(id: "GHSA-1", check: :advisories, kind: :security, severity: :high, package: "plug", message: "x")

    finding_jason =
      Finding.new(id: "GHSA-1", check: :advisories, kind: :security, severity: :high, package: "jason", message: "x")

    assert %{waived: %{}} = Policy.waive(policy, finding_plug, @today)
    refute Policy.waive(policy, finding_jason, @today).waived
  end

  test "lock waivers are scoped to the app or package they name" do
    today = @today

    git_finding =
      Finding.new(
        check: :lock_changes,
        kind: :integrity,
        severity: :high,
        package: "foo",
        rule: :git_ref,
        message: "git ref changed"
      )

    other_git_finding = %{git_finding | package: "bar"}

    policy = %Policy{
      allow_git_refs: [%{app: "bar", reason: "known ref move", expires: "2026-12-01"}]
    }

    refute Policy.waive(policy, git_finding, today).waived
    assert %{waived: %{}} = Policy.waive(policy, other_git_finding, today)

    downgrade =
      Finding.new(
        check: :lock_changes,
        kind: :integrity,
        severity: :high,
        package: "foo",
        rule: :downgrade,
        message: "downgraded"
      )

    # A waiver with no :package key is not a wildcard.
    no_package = %Policy{allow_downgrades: [%{reason: "temporary", expires: "2026-12-01"}]}
    refute Policy.waive(no_package, downgrade, today).waived

    scoped = %Policy{allow_downgrades: [%{package: "bar", reason: "temporary", expires: "2026-12-01"}]}
    refute Policy.waive(scoped, downgrade, today).waived
    assert %{waived: %{}} = Policy.waive(scoped, %{downgrade | package: "bar"}, today)
  end

  test "expired waivers stop applying" do
    policy = %Policy{
      ignore_advisories: [waiver(%{package: "plug", id: "GHSA-1", expires: "2026-01-01"})]
    }

    finding =
      Finding.new(id: "GHSA-1", check: :advisories, kind: :security, severity: :high, package: "plug", message: "x")

    refute Policy.waive(policy, finding, @today).waived
  end
end
