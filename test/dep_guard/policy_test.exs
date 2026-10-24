defmodule DepGuard.PolicyTest do
  use ExUnit.Case, async: true

  alias DepGuard.Policy

  @today ~D[2026-10-24]
  @packages %{"plug" => "1.16.0", "jason" => "1.4.4"}

  defp waiver(attrs) do
    Map.merge(
      %{id: "CVE-2026-0001", package: "plug", reason: "not reachable", expires: "2026-12-01"},
      attrs
    )
  end

  defp problems(policy_attrs), do: Policy.problems(struct(Policy, policy_attrs), @packages, @today)

  test "loading a missing file gives the strict default policy" do
    assert {:ok, %Policy{ignore_advisories: [], allowed_repos: ["hexpm"], require_outer_checksum: true}} =
             Policy.load("/nonexistent/.dep_guard.exs")
  end

  test "loading rejects unknown keys (typos must not weaken the policy)" do
    path = Path.join(System.tmp_dir!(), "dep_guard_policy_#{System.unique_integer([:positive])}.exs")
    File.write!(path, "%{ignore_advisory: []}")
    on_exit(fn -> File.rm(path) end)

    assert {:error, message} = Policy.load(path)
    assert message =~ "unknown keys"
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

    assert [message] = problems(ignore_retirements: [%{package: "plug", version: "1.0.0", reason: "r", expires: "2026-12-01"}])
    assert message =~ "pinned to 1.0.0 but mix.lock has 1.16.0"
  end

  test "malformed lists are reported, not crashed on" do
    assert [_] = problems(ignore_advisories: ["CVE-1"])
    assert [_] = problems(allowed_git: [%{app: "x"}])
    assert [_] = problems(allowed_repos: [:hexpm])
  end

  test "hex_env always sets both variables and unsets them when empty" do
    assert Policy.hex_env(%Policy{}, @today) == [
             {"HEX_IGNORE_ADVISORIES", nil},
             {"HEX_IGNORE_RETIREMENTS", nil}
           ]
  end

  test "hex_env passes only unexpired waivers, with aliases" do
    policy = %Policy{
      ignore_advisories: [
        waiver(%{id: "GHSA-aaaa", aliases: ["CVE-2026-1111"]}),
        waiver(%{id: "CVE-OLD", expires: "2026-01-01"})
      ],
      ignore_retirements: [
        %{package: "plug", version: "1.16.0", reason: "r", expires: "2026-12-01"},
        %{package: "jason", reason: "r", expires: "2026-12-01"}
      ]
    }

    assert [{"HEX_IGNORE_ADVISORIES", advisories}, {"HEX_IGNORE_RETIREMENTS", retirements}] =
             Policy.hex_env(policy, @today)

    assert advisories == "GHSA-aaaa,CVE-2026-1111"
    assert retirements == "plug@1.16.0,jason"
    assert Policy.advisory_ids(policy, @today) == ["GHSA-aaaa", "CVE-2026-1111"]
  end

  test "allowed_downgrades only includes unexpired waivers" do
    policy = %Policy{
      allow_downgrades: [
        %{package: "plug", reason: "r", expires: "2026-12-01"},
        %{package: "jason", reason: "r", expires: "2026-01-01"}
      ]
    }

    assert Policy.allowed_downgrades(policy, @today) == ["plug"]
  end
end
