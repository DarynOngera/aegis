defmodule DepGuard.CLITodayTest do
  # Not async: it changes a process-wide environment variable.
  use ExUnit.Case, async: false

  alias DepGuard.CLI

  setup do
    root = Path.join(System.tmp_dir!(), "dep_guard_today_#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)

    File.write!(
      Path.join(root, "mix.exs"),
      "defmodule D.MixProject do\n  use Mix.Project\n  def project, do: [app: :d]\nend\n"
    )

    File.write!(
      Path.join(root, "mix.lock"),
      ~s|%{"jason": {:hex, :jason, "1.4.4", "#{String.duplicate("a", 64)}", [:mix], [], "hexpm", "#{String.duplicate("b", 64)}"}}|
    )

    previous = System.get_env("DEP_GUARD_ALLOW_TODAY")

    on_exit(fn ->
      File.rm_rf(root)

      if previous,
        do: System.put_env("DEP_GUARD_ALLOW_TODAY", previous),
        else: System.delete_env("DEP_GUARD_ALLOW_TODAY")
    end)

    {:ok, root: root}
  end

  test "--today is refused without the opt-in", %{root: root} do
    System.delete_env("DEP_GUARD_ALLOW_TODAY")

    assert {:error, message} =
             CLI.run(["scan", "--root", root, "--offline", "--allow-skipped", "--today", "2020-01-01"])

    assert message =~ "DEP_GUARD_ALLOW_TODAY=1"
  end

  test "--today is accepted with the opt-in", %{root: root} do
    System.put_env("DEP_GUARD_ALLOW_TODAY", "1")

    assert {:ok, _output, 0} =
             CLI.run(["scan", "--root", root, "--offline", "--allow-skipped", "--today", "2020-01-01"])
  end

  test "an unset --today uses the real date and records it", %{root: root} do
    System.delete_env("DEP_GUARD_ALLOW_TODAY")

    assert {:ok, output, 0} = CLI.run(["scan", "--root", root, "--offline", "--allow-skipped", "--format", "json"])
    inputs = JSON.decode!(output)["inputs"]

    assert inputs["evaluated_on"] == Date.to_iso8601(Date.utc_today())
    assert inputs["today_override"] == false
  end
end
