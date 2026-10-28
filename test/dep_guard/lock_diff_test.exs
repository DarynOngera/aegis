defmodule DepGuard.LockDiffTest do
  use ExUnit.Case, async: true

  alias DepGuard.Lock.Entry
  alias DepGuard.LockDiff

  @sha_a String.duplicate("a", 40)
  @sha_b String.duplicate("b", 40)
  @checksum String.duplicate("c", 64)
  @checksum2 String.duplicate("d", 64)
  @outer String.duplicate("e", 64)

  defp hex(app, version, opts \\ []) do
    %Entry{
      app: app,
      package: Keyword.get(opts, :package, app),
      source: :hex,
      version: version,
      checksum: Keyword.get(opts, :checksum, @checksum),
      outer_checksum: Keyword.get(opts, :outer, @outer),
      repo: Keyword.get(opts, :repo, "hexpm")
    }
  end

  defp git(app, url, ref), do: %Entry{app: app, source: :git, url: url, ref: ref}

  defp run(old, new, opts \\ []) do
    to_map = fn list -> Map.new(list, &{&1.app, &1}) end
    opts = Map.merge(%{downgrades: [], git_refs: [], today: ~D[2026-10-24]}, Map.new(opts))
    old |> to_map.() |> LockDiff.diff(to_map.(new)) |> LockDiff.findings(opts)
  end

  defp errors(findings), do: for(%{kind: kind, message: message, waived: nil} <- findings, kind != :notice, do: message)
  defp notices(findings), do: for(%{kind: :notice, message: message} <- findings, do: message)

  test "plain upgrade is fine" do
    assert run([hex("plug", "1.15.0")], [hex("plug", "1.16.0", checksum: @checksum2)]) == []
  end

  test "same version with a different checksum is an integrity error" do
    findings = run([hex("plug", "1.16.0")], [hex("plug", "1.16.0", checksum: @checksum2)])
    assert [message] = errors(findings)
    assert message =~ "checksum changed but the version did not"
    assert Enum.all?(findings, &(&1.kind == :integrity))
  end

  test "removing a checksum is an error" do
    findings = run([hex("plug", "1.16.0")], [%{hex("plug", "1.16.0") | checksum: nil}])
    assert [message] = errors(findings)
    assert message =~ "checksum was removed"
  end

  test "an older lock gaining an outer checksum is a notice" do
    old = %{hex("plug", "1.16.0") | outer_checksum: nil}
    findings = run([old], [hex("plug", "1.16.0")])
    assert errors(findings) == []
    assert Enum.any?(notices(findings), &(&1 =~ "outer checksum added"))
  end

  test "downgrade is an error unless waived" do
    assert [message] = errors(run([hex("plug", "1.16.0")], [hex("plug", "1.15.0", checksum: @checksum2)]))
    assert message =~ "downgraded 1.16.0 -> 1.15.0"

    waived = [%{package: "plug", reason: "r", expires: "2026-12-01"}]
    findings = run([hex("plug", "1.16.0")], [hex("plug", "1.15.0", checksum: @checksum2)], downgrades: waived)

    assert errors(findings) == []
    assert [%{waived: %{}}] = findings
    assert hd(findings).rule == :downgrade
  end

  test "added and removed dependencies are notices" do
    findings = run([hex("old", "1.0.0")], [hex("fresh", "2.0.0")])
    assert errors(findings) == []
    assert Enum.any?(notices(findings), &(&1 =~ "new dependency fresh 2.0.0"))
    assert Enum.any?(notices(findings), &(&1 =~ "removed dependency old 1.0.0"))
  end

  test "source and repo changes are errors" do
    assert [message] = errors(run([hex("x", "1.0.0")], [git("x", "https://e.com/x.git", @sha_a)]))
    assert message =~ "source changed from hex to git"

    assert [message] = errors(run([hex("x", "1.0.0")], [hex("x", "1.0.0", repo: "hexpm:other")]))
    assert message =~ "Hex repo changed"
  end

  test "a package or lock-key rename is an error" do
    assert [message] = errors(run([hex("x", "1.0.0", package: "old")], [hex("x", "1.0.0", package: "new")]))
    assert message =~ "package changed from old to new"

    findings = run([hex("old_app", "1.0.0", package: "pkg")], [hex("new_app", "1.0.0", package: "pkg")])
    assert [message] = errors(findings)
    assert message =~ "lock key renamed old_app -> new_app"
  end

  test "git URL change is an error, ref change is an error unless waived" do
    assert [message] =
             errors(run([git("x", "https://e.com/x.git", @sha_a)], [git("x", "https://evil.com/x.git", @sha_a)]))

    assert message =~ "git URL changed"

    findings = run([git("x", "https://e.com/x.git", @sha_a)], [git("x", "https://e.com/x.git", @sha_b)])
    assert [message] = errors(findings)
    assert message =~ "git ref changed"

    waived = [%{app: "x", reason: "reviewed", expires: "2026-12-01"}]

    findings =
      run([git("x", "https://e.com/x.git", @sha_a)], [git("x", "https://e.com/x.git", @sha_b)], git_refs: waived)

    assert errors(findings) == []
    assert [%{rule: :git_ref, waived: %{}}] = findings
  end

  test "non-semver versions are not misreported as downgrades" do
    assert errors(run([hex("x", "2.0")], [hex("x", "1.0", checksum: @checksum2)])) == []
  end

  test "a tools/deps change without a version change is a notice" do
    old = %{hex("plug", "1.16.0") | raw_sha256: "a"}
    new = %{hex("plug", "1.16.0") | raw_sha256: "b"}

    findings = run([old], [new])
    assert errors(findings) == []
    assert Enum.any?(notices(findings), &(&1 =~ "lock entry changed without a version change"))
  end
end
