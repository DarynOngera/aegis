defmodule DepGuard.SuiteTest do
  use ExUnit.Case, async: true

  # Regression: the module tag set by the macro must not shadow the `:dep_guard`
  # context key (it once did, and every check received `true` instead of the context).
  defmodule Clean do
    use DepGuard.Suite,
      root: Path.expand("../fixtures/clean", __DIR__),
      eef_feed: false
  end

  test "the macro defines the offline tests and the online tests tagged :online" do
    tests = Clean.__info__(:functions) |> Enum.map(&elem(&1, 0)) |> Enum.map(&to_string/1)
    assert Enum.count(tests, &String.starts_with?(&1, "test ")) == 6
    assert Enum.any?(tests, &(&1 =~ "mix hex.audit"))
    assert Enum.any?(tests, &(&1 =~ "mix deps.audit"))
    refute Enum.any?(tests, &(&1 =~ "EEF"))
  end
end
