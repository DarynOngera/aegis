defmodule DepGuard.HexApiTest do
  use ExUnit.Case, async: true

  alias DepGuard.HexApi

  defp package(name, version, repo \\ "hexpm") do
    %{name: name, version: version, repo: repo, app: name}
  end

  defp server(body, path) do
    server = DepGuard.TestHttp.start(%{path => JSON.encode!(body)})
    on_exit(fn -> DepGuard.TestHttp.stop(server) end)
    server
  end

  defp cache do
    dir = Path.join(System.tmp_dir!(), "dep_guard_hexcache_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  test "reports a security advisory from the Hex API" do
    body = %{
      "retirements" => %{},
      "security_advisories" => [
        %{
          "id" => "GHSA-qpmc-wprv-x746",
          "aliases" => ["CVE-2019-15160"],
          "summary" => "Inline DTD allows XML bomb attack",
          "cvss_rating" => "high",
          "affected" => ["< 0.7.0"],
          "withdrawn_at" => nil
        }
      ]
    }

    server = server(body, "/packages/sweet_xml")

    assert %{status: :ok, findings: [finding]} =
             HexApi.check([package("sweet_xml", "0.6.6")], base_url: server.url, cache_dir: cache())

    assert finding.id == "GHSA-qpmc-wprv-x746"
    assert finding.aliases == ["CVE-2019-15160"]
    assert finding.severity == :high
    assert finding.kind == :security
    assert finding.message =~ "sweet_xml 0.6.6"
    assert finding.sources == ["hex_api"]
  end

  test "reports a retired version" do
    body = %{
      "retirements" => %{
        "1.3.2" => %{"message" => "Custom commands are broken", "reason" => "other"}
      },
      "security_advisories" => []
    }

    server = server(body, "/packages/distillery")

    assert %{status: :ok, findings: [finding]} =
             HexApi.check([package("distillery", "1.3.2")], base_url: server.url, cache_dir: cache())

    assert finding.check == :retirements
    assert finding.id == "retirement:distillery@1.3.2"
    assert finding.message =~ "Custom commands are broken"
  end

  test "a pre-release inside the affected range is reported" do
    body = %{
      "retirements" => %{},
      "security_advisories" => [%{"id" => "GHSA-pre", "affected" => ["< 1.0.0"], "cvss_rating" => "high"}]
    }

    server = server(body, "/packages/x")

    assert %{status: :ok, findings: [%{id: "GHSA-pre"}]} =
             HexApi.check([package("x", "1.0.0-rc.1")], base_url: server.url, cache_dir: cache())
  end

  test "a withdrawn advisory is skipped and a clean version passes" do
    body = %{
      "retirements" => %{},
      "security_advisories" => [
        %{"id" => "GHSA-old", "affected" => ["< 9.9.9"], "withdrawn_at" => "2026-01-01T00:00:00Z"}
      ]
    }

    server = server(body, "/packages/sweet_xml")

    assert %{status: :ok, findings: []} =
             HexApi.check([package("sweet_xml", "1.0.0")], base_url: server.url, cache_dir: cache())
  end

  test "an unevaluable affected range is operational" do
    body = %{
      "retirements" => %{},
      "security_advisories" => [%{"id" => "GHSA-x", "affected" => ["definitely not a requirement"]}]
    }

    server = server(body, "/packages/x")

    assert %{status: :error, findings: [%{kind: :operational}]} =
             HexApi.check([package("x", "1.0.0")], base_url: server.url, cache_dir: cache())
  end

  test "malformed retirement data is operational, not a crash" do
    for retirements <- ["not-a-map", [%{"1.0.0" => "x"}], 42] do
      body = %{"retirements" => retirements, "security_advisories" => []}
      server = server(body, "/packages/broken")

      assert %{status: :error, findings: [%{kind: :operational, message: message}]} =
               HexApi.check([package("broken", "1.0.0")], base_url: server.url, cache_dir: cache())

      assert message =~ "unexpected shape"
    end
  end

  test "malformed advisory fields do not crash the merge" do
    body = %{
      "retirements" => %{},
      "security_advisories" => [
        %{
          "id" => "GHSA-malformed",
          "aliases" => "not-a-list",
          "summary" => %{"nested" => true},
          "affected" => ["< 2.0.0"],
          "cvss_rating" => "high"
        }
      ]
    }

    server = server(body, "/packages/x")

    assert %{status: :ok, findings: [finding]} =
             HexApi.check([package("x", "1.0.0")], base_url: server.url, cache_dir: cache())

    assert finding.id == "GHSA-malformed"
    assert finding.aliases == []
    assert finding.message =~ "security advisory"
  end

  test "a non-string affected entry is operational, not a crash" do
    body = %{
      "retirements" => %{},
      "security_advisories" => [%{"id" => "GHSA-x", "affected" => [1, nil], "cvss_rating" => "high"}]
    }

    server = server(body, "/packages/x")

    assert %{status: :error, findings: [%{kind: :operational}]} =
             HexApi.check([package("x", "1.0.0")], base_url: server.url, cache_dir: cache())
  end

  test "a private repo is uncovered, not clean" do
    assert %{status: :uncovered, findings: [%{kind: :operational, message: message}], stats: %{uncovered: 1}} =
             HexApi.check([package("internal", "1.0.0", "hexpm:acme")], cache_dir: cache())

    assert message =~ "private Hex repo"
  end

  test "a 404 is uncovered and a 500 is an error" do
    not_found = DepGuard.TestHttp.start(%{})
    on_exit(fn -> DepGuard.TestHttp.stop(not_found) end)

    assert %{status: :uncovered} =
             HexApi.check([package("gone", "1.0.0")], base_url: not_found.url, cache_dir: cache())

    failing = DepGuard.TestHttp.start(%{"/packages/boom" => {500, "{}"}})
    on_exit(fn -> DepGuard.TestHttp.stop(failing) end)

    assert %{status: :error, findings: [%{kind: :operational}]} =
             HexApi.check([package("boom", "1.0.0")], base_url: failing.url, cache_dir: cache())
  end

  test "responses are cached" do
    body = %{"retirements" => %{}, "security_advisories" => []}
    dir = cache()
    server = server(body, "/packages/jason")

    first = HexApi.check([package("jason", "1.4.4")], base_url: server.url, cache_dir: dir)
    assert first.stats.requests == 1
    assert first.stats.cached == 0

    second = HexApi.check([package("jason", "1.4.4")], base_url: server.url, cache_dir: dir)
    assert second.stats.requests == 0
    assert second.stats.cached == 1
  end
end
