defmodule DepGuard.LockTest do
  use ExUnit.Case, async: true

  alias DepGuard.{Literal, Lock}

  @sha "0123456789abcdef0123456789abcdef01234567"

  @lock ~s"""
  %{
    "jason": {:hex, :jason, "1.4.4", "aaaa", [:mix], [], "hexpm", "bbbb"},
    "mylib": {:git, "https://github.com/acme/mylib.git", "#{@sha}", [branch: "main"]},
  }
  """

  test "parses hex and git entries" do
    assert {:ok, lock} = Lock.parse_entries(@lock)

    assert %{source: :hex, package: "jason", version: "1.4.4", checksum: "aaaa", outer_checksum: "bbbb", repo: "hexpm"} =
             lock["jason"]

    assert %{source: :git, url: "https://github.com/acme/mylib.git", ref: @sha} = lock["mylib"]
    assert Lock.hex_versions(lock) == %{"jason" => "1.4.4"}
  end

  test "accepts older lock formats without an outer checksum" do
    assert {:ok, lock} = Lock.parse_entries(~s(%{"a": {:hex, :a, "1.0.0", "cc", [:mix], [], "hexpm"}}))
    assert lock["a"].outer_checksum == nil
  end

  test "refuses a lock that contains code" do
    assert {:error, message} = Lock.parse_entries(~S|%{"a": System.cmd("echo", ["pwned"])}|)
    assert message =~ "plain data"
  end

  test "refuses interpolation and non-map content" do
    assert {:error, _} = Lock.parse_entries(~S|%{"a": "#{System.get_env("HOME")}"}|)
    assert {:error, "must contain a single map"} = Lock.parse_entries("[1, 2]")
  end

  test "reports unparsable input" do
    assert {:error, message} = Lock.parse_entries("%{")
    assert message =~ "does not parse"
  end

  test "integrity: clean lock has no problems" do
    {:ok, lock} = Lock.parse_entries(@lock)
    assert Lock.integrity_problems(lock) == []
  end

  test "integrity: flags missing checksums, missing outer checksum, unpinned git" do
    {:ok, lock} =
      Lock.parse_entries(~S"""
      %{
        "nocs": {:hex, :nocs, "1.0.0", nil, [:mix], [], "hexpm", "o"},
        "noouter": {:hex, :noouter, "1.0.0", "c", [:mix], [], "hexpm"},
        "branchy": {:git, "https://example.com/x.git", "main", []},
        "weird": {:something, :else},
      }
      """)

    problems = Lock.integrity_problems(lock)
    assert Enum.any?(problems, &(&1 =~ "nocs 1.0.0: lock entry has no checksum"))
    assert Enum.any?(problems, &(&1 =~ "noouter 1.0.0: lock entry has no outer checksum"))
    assert Enum.any?(problems, &(&1 =~ "branchy: git dependency is not pinned"))
    assert Enum.any?(problems, &(&1 =~ "weird: unrecognised"))
  end

  test "integrity: outer checksum requirement can be switched off" do
    {:ok, lock} = Lock.parse_entries(~s(%{"a": {:hex, :a, "1.0.0", "cc", [:mix], [], "hexpm"}}))
    assert Lock.integrity_problems(lock, false) == []
  end

  test "Literal accepts nested data" do
    assert {:ok, %{a: [1, {:x, "y"}, {1, 2, 3}]}} = Literal.parse(~s(%{a: [1, {:x, "y"}, {1, 2, 3}]}))
  end
end
