defmodule DepGuard.LockDiffTest do
  use ExUnit.Case, async: true

  alias DepGuard.Lock.Entry
  alias DepGuard.LockDiff

  defp hex(app, version, opts \\ []) do
    %Entry{
      app: app,
      package: app,
      source: :hex,
      version: version,
      checksum: Keyword.get(opts, :checksum, "c1"),
      outer_checksum: Keyword.get(opts, :outer, "o1"),
      repo: Keyword.get(opts, :repo, "hexpm")
    }
  end

  defp git(app, url, ref), do: %Entry{app: app, source: :git, url: url, ref: ref}

  defp run(old, new, allowed \\ []) do
    to_map = fn list -> Map.new(list, &{&1.app, &1}) end
    old |> to_map.() |> LockDiff.diff(to_map.(new)) |> LockDiff.findings(allowed)
  end

  defp errors(findings), do: for(%{severity: :error, message: m} <- findings, do: m)
  defp notices(findings), do: for(%{severity: :notice, message: m} <- findings, do: m)

  test "plain upgrade is fine" do
    assert run([hex("plug", "1.15.0")], [hex("plug", "1.16.0", checksum: "c2", outer: "o2")]) == []
  end

  test "same version with a different checksum is an error" do
    findings = run([hex("plug", "1.16.0")], [hex("plug", "1.16.0", checksum: "EVIL")])
    assert [message] = errors(findings)
    assert message =~ "checksum changed but the version did not"
  end

  test "an older lock gaining an outer checksum is not tampering" do
    old = %{hex("plug", "1.16.0") | outer_checksum: nil}
    assert run([old], [hex("plug", "1.16.0")]) == []
  end

  test "downgrade is an error unless waived" do
    assert [message] = errors(run([hex("plug", "1.16.0")], [hex("plug", "1.15.0", checksum: "c0")]))
    assert message =~ "downgraded 1.16.0 -> 1.15.0"

    findings = run([hex("plug", "1.16.0")], [hex("plug", "1.15.0", checksum: "c0")], ["plug"])
    assert errors(findings) == []
    assert [note] = notices(findings)
    assert note =~ "waived"
  end

  test "added and removed dependencies are notices" do
    findings = run([hex("old", "1.0.0")], [hex("fresh", "2.0.0")])
    assert errors(findings) == []
    assert Enum.any?(notices(findings), &(&1 =~ "new dependency fresh 2.0.0"))
    assert Enum.any?(notices(findings), &(&1 =~ "removed dependency old 1.0.0"))
  end

  test "source and repo changes are errors" do
    sha = String.duplicate("a", 40)

    assert [m] = errors(run([hex("x", "1.0.0")], [git("x", "https://e.com/x.git", sha)]))
    assert m =~ "source changed from hex to git"

    assert [m] = errors(run([hex("x", "1.0.0")], [hex("x", "1.0.0", repo: "hexpm:other")]))
    assert m =~ "Hex repo changed"
  end

  test "git URL change is an error, ref change is a notice" do
    a = String.duplicate("a", 40)
    b = String.duplicate("b", 40)

    assert [m] = errors(run([git("x", "https://e.com/x.git", a)], [git("x", "https://evil.com/x.git", a)]))
    assert m =~ "git URL changed"

    findings = run([git("x", "https://e.com/x.git", a)], [git("x", "https://e.com/x.git", b)])
    assert errors(findings) == []
    assert [_] = notices(findings)
  end

  test "non-semver versions are not misreported as downgrades" do
    assert errors(run([hex("x", "2.0")], [hex("x", "1.0", checksum: "c2")])) == []
  end
end
