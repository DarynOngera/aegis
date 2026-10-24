defmodule DepGuard.ChecksTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias DepGuard.Checks

  @sha String.duplicate("a", 40)
  @today ~D[2026-10-24]

  setup do
    root = Path.join(System.tmp_dir!(), "dep_guard_#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)
    {:ok, root: root}
  end

  defp hex_line(app, version, checksum \\ "c1") do
    "  \"#{app}\": {:hex, :#{app}, \"#{version}\", \"#{checksum}\", [:mix], [], \"hexpm\", \"o1\"},\n"
  end

  defp git_line(app, url), do: "  \"#{app}\": {:git, \"#{url}\", \"#{@sha}\", []},\n"

  defp write_lock(root, lines), do: File.write!(Path.join(root, "mix.lock"), "%{\n" <> Enum.join(lines) <> "}\n")
  defp write_policy(root, source), do: File.write!(Path.join(root, ".dep_guard.exs"), source)

  defp context!(root) do
    {:ok, ctx} = Checks.context(root: root, today: @today, mix_env: :test)
    ctx
  end

  defp git!(root, args) do
    {_output, 0} =
      System.cmd("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false" | args],
        cd: root,
        stderr_to_stdout: true
      )
  end

  test "context fails clearly without a mix.lock", %{root: root} do
    assert {:error, message} = Checks.context(root: root, mix_env: :test)
    assert message =~ "not found"
  end

  test "context fails on a malformed policy file", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])
    write_policy(root, ~S|%{ignore_advisory: []}|)
    assert {:error, message} = Checks.context(root: root, mix_env: :test)
    assert message =~ "unknown keys"
  end

  test "lockfile check passes on a clean lock", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])
    assert Checks.lockfile(context!(root)) == []
  end

  test "sources: git deps need an allowed_git entry with the same URL", %{root: root} do
    url = "https://github.com/acme/mylib.git"
    write_lock(root, [hex_line("a", "1.0.0"), git_line("mylib", url)])

    assert [problem] = Checks.sources(context!(root))
    assert problem =~ "mylib"
    assert problem =~ "not listed in allowed_git"

    write_policy(root, ~s|%{allowed_git: [%{app: "mylib", url: "#{url}"}]}|)
    assert Checks.sources(context!(root)) == []

    write_policy(root, ~S|%{allowed_git: [%{app: "mylib", url: "https://evil.example/mylib.git"}]}|)
    assert [problem] = Checks.sources(context!(root))
    assert problem =~ "allowed_git expects"
  end

  test "sources: unexpected Hex repo is flagged", %{root: root} do
    File.write!(
      Path.join(root, "mix.lock"),
      "%{\n  \"a\": {:hex, :a, \"1.0.0\", \"c\", [:mix], [], \"hexpm:other\", \"o\"},\n}\n"
    )

    assert [problem] = Checks.sources(context!(root))
    assert problem =~ "not in allowed_repos"
  end

  test "policy hygiene reports expired waivers", %{root: root} do
    write_lock(root, [hex_line("a", "1.0.0")])
    write_policy(root, ~S|%{ignore_retirements: [%{package: "a", reason: "r", expires: "2026-01-01"}]}|)

    assert [problem] = Checks.policy_hygiene(context!(root))
    assert problem =~ "expired on 2026-01-01"
  end

  test "project_ignores passes for a project without hex ignore config" do
    assert Checks.project_ignores() == []
  end

  describe "lock_changes (uses git)" do
    setup %{root: root} do
      git!(root, ["init", "-q"])
      :ok
    end

    test "same version with a different checksum is reported", %{root: root} do
      write_lock(root, [hex_line("a", "1.0.0", "good")])
      git!(root, ["add", "mix.lock"])
      git!(root, ["commit", "-q", "-m", "base"])

      write_lock(root, [hex_line("a", "1.0.0", "EVIL")])

      assert [problem] = Checks.lock_changes(context!(root), "HEAD")
      assert problem =~ "checksum changed but the version did not"
    end

    test "an unchanged lock has no problems", %{root: root} do
      write_lock(root, [hex_line("a", "1.0.0")])
      git!(root, ["add", "mix.lock"])
      git!(root, ["commit", "-q", "-m", "base"])

      assert Checks.lock_changes(context!(root), "HEAD") == []
    end

    test "a base without mix.lock means every dependency is new (notices only)", %{root: root} do
      File.write!(Path.join(root, "README.md"), "x")
      git!(root, ["add", "README.md"])
      git!(root, ["commit", "-q", "-m", "base"])

      write_lock(root, [hex_line("a", "1.0.0")])

      output = capture_io(fn -> assert Checks.lock_changes(context!(root), "HEAD") == [] end)
      assert output =~ "new dependency a 1.0.0"
    end

    test "an unknown ref is reported, not crashed on", %{root: root} do
      write_lock(root, [hex_line("a", "1.0.0")])
      assert [problem] = Checks.lock_changes(context!(root), "origin/does-not-exist")
      assert problem =~ "cannot compare mix.lock"
    end
  end
end
