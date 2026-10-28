defmodule DepGuard.MixExsTest do
  use ExUnit.Case, async: true

  alias DepGuard.MixExs

  defp scan(source) do
    dir = Path.join(System.tmp_dir!(), "dep_guard_mixexs_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    path = Path.join(dir, "mix.exs")
    File.write!(path, source)
    on_exit(fn -> File.rm_rf(dir) end)
    MixExs.scan(path)
  end

  test "a project without hex ignore config passes" do
    assert {:ok, []} =
             scan("""
             defmodule Demo.MixProject do
               use Mix.Project
               def project, do: [app: :demo, deps: []]
             end
             """)
  end

  test "empty ignore lists pass" do
    assert {:ok, []} =
             scan("""
             defmodule Demo.MixProject do
               use Mix.Project
               def project do
                 [app: :demo, hex: [ignore_advisories: [], ignore_retirements: []]]
               end
             end
             """)
  end

  test "a literal ignore list is a policy finding" do
    assert {:ok, [finding]} =
             scan("""
             defmodule Demo.MixProject do
               use Mix.Project
               def project do
                 [app: :demo, hex: [ignore_advisories: ["GHSA-1"]]]
               end
             end
             """)

    assert finding.check == :mix_exs
    assert finding.kind == :policy
    assert finding.message =~ "ignore_advisories"
  end

  test "a computed hex option is reported, never guessed" do
    assert {:ok, [finding]} =
             scan("""
             defmodule Demo.MixProject do
               use Mix.Project
               def project do
                 [app: :demo, hex: hex_config()]
               end
               defp hex_config, do: []
             end
             """)

    assert finding.message =~ "cannot be inspected"
  end

  test "a missing or unparsable mix.exs is an error" do
    assert {:error, message} = MixExs.scan("/nonexistent/mix.exs")
    assert message =~ "not found"

    assert {:error, message} = scan("defmodule Broken do")
    assert message =~ "does not parse"
  end
end
