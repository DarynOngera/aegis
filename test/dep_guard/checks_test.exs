defmodule DepGuard.ChecksTest do
  use ExUnit.Case, async: true

  alias DepGuard.{Checks, Finding}

  @sha String.duplicate("a", 40)
  @checksum String.duplicate("c", 64)
  @outer String.duplicate("d", 64)
  @today ~D[2026-10-24]

  setup do
    root = Path.join(System.tmp_dir!(), "dep_guard_#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)
    {:ok, root: root}
  end

  defp hex_line(app, version, checksum \\ @checksum) do
    "  \"#{app}\": {:hex, :#{app}, \"#{version}\", \"#{checksum}\", [:mix], [], \"hexpm\", \"#{@outer}\"},\n"
  end

  defp git_line(app, url), do: "  \"#{app}\": {:git, \"#{url}\", \"#{@sha}\", []},\n"
  defp write_lock(root, lines), do: File.write!(Path.join(root, "mix.lock"), "%{\n" <> Enum.join(lines) <> "}\n")
  defp write_policy(root, source), do: File.write!(Path.join(root, ".dep_guard.exs"), source)

  defp context!(root, opts \\ []) do
    {:ok, ctx} = Checks.context([root: root, today: @today] ++ opts)
    ctx
  end

  defp messages(findings), do: Enum.map(findings, & &1.message)

  defp git!(root, args) do
    {_output, 0} =
      System.cmd("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false" | args],
        cd: root,
        stderr_to_stdout: true
      )
  end

  test "context fails clearly without a mix.lock", %{root: root} do
    assert {:error, message} = Checks.context(root: root)
    assert message =~ "not found"
  end

  test "context fails on a malformed policy file", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])
    write_policy(root, ~S|%{ignore_advisory: []}|)
    assert {:error, message} = Checks.context(root: root)
    assert message =~ "unknown keys"
  end

  test "context rejects a wrong-typed org policy instead of crashing", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])
    org = Path.join(root, "org.exs")
    File.write!(org, ~S|%{allowed_repos: "hexpm"}|)

    assert {:error, message} = Checks.context(root: root, org_policy: org)
    assert message =~ "allowed_repos has the wrong type"
  end

  test "lockfile check passes on a clean lock", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])
    assert Checks.lockfile(context!(root)) == []
  end

  test "sources: git deps need an allowed_git entry with the same URL", %{root: root} do
    url = "https://github.com/acme/mylib.git"
    write_lock(root, [hex_line("a", "1.0.0"), git_line("mylib", url)])
    org = Path.join(root, "org.exs")

    assert [finding] = Checks.sources(context!(root))
    assert finding.message =~ "mylib"
    assert finding.message =~ "not listed in allowed_git"

    File.write!(org, ~s|%{allowed_git: [%{app: "mylib", url: "#{url}"}]}|)
    assert Checks.sources(context!(root, org_policy: org)) == []

    File.write!(org, ~S|%{allowed_git: [%{app: "mylib", url: "https://evil.example/mylib.git"}]}|)
    assert [finding] = Checks.sources(context!(root, org_policy: org))
    assert finding.message =~ "allowed_git expects"
  end

  test "sources: unexpected Hex repo is flagged", %{root: root} do
    File.write!(
      Path.join(root, "mix.lock"),
      "%{\n  \"a\": {:hex, :a, \"1.0.0\", \"#{@checksum}\", [:mix], [], \"hexpm:other\", \"#{@outer}\"},\n}\n"
    )

    assert [finding] = Checks.sources(context!(root))
    assert finding.message =~ "not in allowed_repos"
  end

  test "policy hygiene reports expired waivers", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])
    write_policy(root, ~S|%{ignore_retirements: [%{package: "a", reason: "r", expires: "2026-01-01"}]}|)

    assert [finding] = Checks.policy_hygiene(context!(root))
    assert finding.message =~ "expired on 2026-01-01"
    assert finding.kind == :policy
    assert finding.severity == :high
  end

  test "project_ignores flags mix.exs ignore configuration", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])

    File.write!(Path.join(root, "mix.exs"), """
    defmodule Demo.MixProject do
      use Mix.Project
      def project, do: [app: :demo, hex: [ignore_retirements: ["a"]]]
    end
    """)

    assert [finding] = Checks.project_ignores(context!(root))
    assert finding.check == :mix_exs
  end

  test "hex_api passes the package name, not just the lock key", %{root: root} do
    File.write!(
      Path.join(root, "mix.lock"),
      "%{\n  \"renamed_app\": {:hex, :real_pkg, \"1.0.0\", \"#{@checksum}\", [:mix], [], \"hexpm\", \"#{@outer}\"},\n}\n"
    )

    body = %{
      "retirements" => %{},
      "security_advisories" => [
        %{"id" => "GHSA-test-1", "affected" => ["< 2.0.0"], "cvss_rating" => "high"}
      ]
    }

    server = DepGuard.TestHttp.start(%{"/packages/real_pkg" => JSON.encode!(body)})
    on_exit(fn -> DepGuard.TestHttp.stop(server) end)

    result = Checks.hex_api(context!(root), base_url: server.url, cache_dir: Path.join(root, "cache"))

    assert result.status == :ok
    assert [finding] = result.findings
    assert finding.id == "GHSA-test-1"
    assert finding.package == "real_pkg"
  end

  describe "lock_changes (uses git)" do
    setup %{root: root} do
      git!(root, ["init", "-q"])
      :ok
    end

    test "same version with a different checksum is reported", %{root: root} do
      write_lock(root, [hex_line("a", "1.0.0", String.duplicate("1", 64))])
      git!(root, ["add", "mix.lock"])
      git!(root, ["commit", "-q", "-m", "base"])

      write_lock(root, [hex_line("a", "1.0.0", String.duplicate("2", 64))])

      assert [finding] = Checks.lock_changes(context!(root), {:ref, "HEAD"})
      assert finding.message =~ "checksum changed but the version did not"
      assert finding.kind == :integrity
    end

    test "an unchanged lock has no findings", %{root: root} do
      write_lock(root, [hex_line("a", "1.0.0")])
      git!(root, ["add", "mix.lock"])
      git!(root, ["commit", "-q", "-m", "base"])

      assert Checks.lock_changes(context!(root), {:ref, "HEAD"}) == []
    end

    test "a base without mix.lock means every dependency is new (notices only)", %{root: root} do
      File.write!(Path.join(root, "README.md"), "x")
      git!(root, ["add", "README.md"])
      git!(root, ["commit", "-q", "-m", "base"])

      write_lock(root, [hex_line("a", "1.0.0")])

      findings = Checks.lock_changes(context!(root), {:ref, "HEAD"})
      assert Enum.all?(findings, &(&1.kind == :notice))
      assert messages(findings) |> Enum.any?(&(&1 =~ "new dependency a 1.0.0"))
    end

    test "an unknown ref is an operational finding, not a crash", %{root: root} do
      write_lock(root, [hex_line("a", "1.0.0")])
      assert [%Finding{kind: :operational}] = Checks.lock_changes(context!(root), {:ref, "origin/does-not-exist"})
    end
  end
end
