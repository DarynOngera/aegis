defmodule DepGuard.LockTest do
  use ExUnit.Case, async: true

  alias DepGuard.{Literal, Lock}

  @sha "0123456789abcdef0123456789abcdef01234567"
  @checksum String.duplicate("a", 64)
  @outer String.duplicate("b", 64)

  @lock ~s"""
  %{
    "jason": {:hex, :jason, "1.4.4", "#{@checksum}", [:mix], [], "hexpm", "#{@outer}"},
    "mylib": {:git, "https://github.com/acme/mylib.git", "#{@sha}", [branch: "main"]},
  }
  """

  test "parses hex and git entries" do
    assert {:ok, lock} = Lock.parse_entries(@lock)

    assert %{source: :hex, package: "jason", version: "1.4.4", repo: "hexpm"} = lock["jason"]
    assert %{source: :git, url: "https://github.com/acme/mylib.git", ref: @sha} = lock["mylib"]
    assert Lock.hex_versions(lock) == %{"jason" => "1.4.4"}
    assert %{"jason" => %{version: "1.4.4", repo: "hexpm", app: "jason"}} = Lock.hex_packages(lock)
  end

  test "accepts older lock formats without an outer checksum" do
    assert {:ok, lock} = Lock.parse_entries(~s(%{"a": {:hex, :a, "1.0.0", "#{@checksum}", [:mix], [], "hexpm"}}))
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

  test "malformed lock entries are errors, not crashes" do
    malformed = [
      ~s|%{%{"x" => 1} => {:hex, :x, "1.0.0", "#{@checksum}", [:mix], [], "hexpm", "#{@outer}"}}|,
      ~s|%{"x" => {:hex, %{a: 1}, "1.0.0", "#{@checksum}", [:mix], [], "hexpm", "#{@outer}"}}|,
      ~s|%{"x" => {:hex, :x, %{a: 1}, "#{@checksum}", [:mix], [], "hexpm", "#{@outer}"}}|,
      ~s|%{"x" => {:hex, :x, "1.0.0", 123, [:mix], [], "hexpm", "#{@outer}"}}|,
      ~s|%{"x" => {:hex, :x, "1.0.0", "#{@checksum}", [:mix], [], 42, "#{@outer}"}}|,
      ~s|%{"x" => {:git, 42, "#{@sha}", []}}|
    ]

    for source <- malformed do
      assert {:error, message} = Lock.parse_entries(source)
      assert is_binary(message)
      assert message != ""
    end
  end

  test "integrity: clean lock has no findings" do
    {:ok, lock} = Lock.parse_entries(@lock)
    assert Lock.integrity_findings(lock) == []
  end

  test "integrity: flags missing, malformed and removed checksums, unpinned git and odd entries" do
    {:ok, lock} =
      Lock.parse_entries(~S"""
      %{
        "nocs": {:hex, :nocs, "1.0.0", nil, [:mix], [], "hexpm", "o"},
        "bad": {:hex, :bad, "1.0.0", "not-a-checksum", [:mix], [], "hexpm", "o"},
        "noouter": {:hex, :noouter, "1.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [], "hexpm"},
        "branchy": {:git, "https://example.com/x.git", "main", []},
        "weird": {:something, :else},
      }
      """)

    findings = Lock.integrity_findings(lock)
    messages = Enum.map(findings, & &1.message)

    assert Enum.any?(messages, &(&1 =~ "nocs 1.0.0: lock entry has no checksum"))
    assert Enum.any?(messages, &(&1 =~ "bad 1.0.0: checksum is not a 64-character hex digest"))
    assert Enum.any?(messages, &(&1 =~ "noouter 1.0.0: lock entry has no outer checksum"))
    assert Enum.any?(messages, &(&1 =~ "branchy: git dependency is not pinned"))
    assert Enum.any?(messages, &(&1 =~ "weird: unrecognised"))
    assert Enum.all?(findings, &(&1.kind == :integrity))
  end

  test "integrity: outer checksum requirement can be switched off" do
    {:ok, lock} = Lock.parse_entries(~s(%{"a": {:hex, :a, "1.0.0", "#{@checksum}", [:mix], [], "hexpm"}}))
    assert Lock.integrity_findings(lock, false) == []
  end

  test "Literal accepts nested data" do
    assert {:ok, %{a: [1, {:x, "y"}, {1, 2, 3}]}} = Literal.parse(~s(%{a: [1, {:x, "y"}, {1, 2, 3}]}))
  end
end
