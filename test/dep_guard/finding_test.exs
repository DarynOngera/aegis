defmodule DepGuard.FindingTest do
  use ExUnit.Case, async: true

  alias DepGuard.Finding

  defp finding(attrs) do
    Finding.new(Map.merge(%{check: :advisories, kind: :security, severity: :high, message: "x"}, Map.new(attrs)))
  end

  test "gating respects severity and waivers" do
    assert Finding.gating?(finding(severity: :high), :high)
    refute Finding.gating?(finding(severity: :medium), :high)
    refute Finding.gating?(finding(severity: :high, waived: %{reason: "r", expires: "2026-12-01"}), :high)
    refute Finding.gating?(finding(kind: :notice, severity: :critical), :low)
    assert Finding.gating?(finding(kind: :operational, severity: :info), :critical)
  end

  test "unknown severity fails closed" do
    assert Finding.gating?(finding(severity: :unknown), :high)
    assert Finding.rank(:unknown) == Finding.rank(:high)
  end

  test "merge keeps the highest severity and unions sources and aliases" do
    a = finding(id: "GHSA-1", severity: :medium, sources: ["hex_api"], aliases: ["CVE-1"])
    b = finding(id: "GHSA-1", severity: :high, sources: ["mix_audit"], aliases: ["CVE-2"])

    merged = Finding.merge(a, b)

    assert merged.severity == :high
    assert merged.sources == ["hex_api", "mix_audit"]
    assert merged.aliases == ["CVE-1", "CVE-2"]
  end

  test "severity strings from the sources are mapped" do
    assert Finding.severity_from_string("HIGH") == :high
    assert Finding.severity_from_string("moderate") == :medium
    assert Finding.severity_from_string(nil) == :unknown
    assert Finding.severity_from_string("bogus") == :unknown
  end
end
