defmodule DepGuard.EefFeedTest do
  use ExUnit.Case, async: true

  alias DepGuard.EefFeed

  defp record(affected_extra) do
    %{
      "id" => "EEF-CVE-2026-0001",
      "aliases" => ["CVE-2026-0001"],
      "affected" => [
        Map.merge(%{"package" => %{"ecosystem" => "Hex", "name" => "esaml"}}, affected_extra)
      ]
    }
  end

  defp range(events), do: %{"ranges" => [%{"type" => "SEMVER", "events" => events}]}

  test "version inside [introduced, fixed) is affected" do
    r = record(range([%{"introduced" => "0"}, %{"fixed" => "4.5.1"}]))

    assert [finding] = EefFeed.record_findings(r, %{"esaml" => "4.5.0"})
    assert finding.message =~ "esaml 4.5.0 is affected by EEF-CVE-2026-0001 (CVE-2026-0001)"
    assert finding.aliases == ["CVE-2026-0001"]
    assert finding.sources == ["eef"]

    assert EefFeed.record_findings(r, %{"esaml" => "4.5.1"}) == []
    assert EefFeed.record_findings(r, %{"esaml" => "5.0.0"}) == []
  end

  test "introduced lower bound is respected" do
    r = record(range([%{"introduced" => "2.0.0"}, %{"fixed" => "2.3.0"}]))
    assert EefFeed.record_findings(r, %{"esaml" => "1.9.0"}) == []
    assert [_] = EefFeed.record_findings(r, %{"esaml" => "2.1.0"})
  end

  test "last_affected is inclusive" do
    r = record(range([%{"introduced" => "0"}, %{"last_affected" => "1.2.0"}]))
    assert [_] = EefFeed.record_findings(r, %{"esaml" => "1.2.0"})
    assert EefFeed.record_findings(r, %{"esaml" => "1.2.1"}) == []
  end

  test "packages not in the lock, or from other ecosystems, are ignored" do
    r = record(range([%{"introduced" => "0"}]))
    assert EefFeed.record_findings(r, %{"other" => "1.0.0"}) == []

    npm = put_in(r, ["affected", Access.at(0), "package", "ecosystem"], "npm")
    assert EefFeed.record_findings(npm, %{"esaml" => "1.0.0"}) == []
  end

  test "fails closed when the range cannot be evaluated or affected is missing" do
    no_info = record(%{})
    assert [%{kind: :operational}] = EefFeed.record_findings(no_info, %{"esaml" => "1.0.0"})

    odd = record(range([%{"introduced" => "0"}, %{"fixed" => "not-a-version"}]))
    assert [%{kind: :operational}] = EefFeed.record_findings(odd, %{"esaml" => "1.0.0"})

    empty = %{"id" => "EEF-EMPTY", "affected" => []}
    assert [%{kind: :operational, message: message}] = EefFeed.record_findings(empty, %{"esaml" => "1.0.0"})
    assert message =~ "no affected entries"

    malformed = %{"id" => "EEF-MALFORMED", "affected" => %{}}
    assert [%{kind: :operational, message: message}] = EefFeed.record_findings(malformed, %{"esaml" => "1.0.0"})
    assert message =~ "no affected entries"
  end

  test "unreadable events fail closed instead of raising" do
    nil_events = %{
      "id" => "EEF-NIL",
      "affected" => [
        %{"package" => %{"ecosystem" => "Hex", "name" => "esaml"}, "ranges" => [%{"type" => "SEMVER", "events" => nil}]}
      ]
    }

    assert [%{kind: :operational, message: message}] = EefFeed.record_findings(nil_events, %{"esaml" => "1.0.0"})
    assert message =~ "could not be evaluated"

    string_events = %{
      "id" => "EEF-STRING",
      "affected" => [
        %{
          "package" => %{"ecosystem" => "Hex", "name" => "esaml"},
          "ranges" => [%{"type" => "SEMVER", "events" => "not-a-list"}]
        }
      ]
    }

    assert [%{kind: :operational}] = EefFeed.record_findings(string_events, %{"esaml" => "1.0.0"})

    map_ranges = %{
      "id" => "EEF-MAP",
      "affected" => [%{"package" => %{"ecosystem" => "Hex", "name" => "esaml"}, "ranges" => %{"type" => "SEMVER"}}]
    }

    assert [%{kind: :operational}] = EefFeed.record_findings(map_ranges, %{"esaml" => "1.0.0"})
  end

  test "withdrawn records are notices, not findings" do
    r = %{"id" => "EEF-GONE", "withdrawn" => "2026-01-01T00:00:00Z", "affected" => []}
    assert [%{kind: :notice}] = EefFeed.record_findings(r, %{"esaml" => "1.0.0"})
  end

  # Shape taken from the live feed (EEF-CVE-2025-4754).
  @live_shape %{
    "id" => "EEF-CVE-2025-4754",
    "aliases" => ["GHSA-f7gq-h8jv-h3cq", "CVE-2025-4754"],
    "affected" => [
      %{
        "package" => %{
          "ecosystem" => "Hex",
          "name" => "ash_authentication_phoenix",
          "purl" => "pkg:hex/ash_authentication_phoenix"
        },
        "ranges" => [%{"type" => "SEMVER", "events" => [%{"introduced" => "0.1.0"}, %{"fixed" => "2.10.0"}]}],
        "versions" => ["2.8.0", "2.9.0"]
      },
      %{
        "ranges" => [
          %{
            "type" => "GIT",
            "repo" => "https://github.com/team-alembic/ash_authentication_phoenix",
            "events" => [%{"introduced" => "05ab4f43"}, %{"fixed" => "a3253fb4"}]
          }
        ]
      }
    ]
  }

  test "matches the real feed shape and ignores package-less GIT entries" do
    assert [finding] = EefFeed.record_findings(@live_shape, %{"ash_authentication_phoenix" => "2.9.0"})
    assert finding.message =~ "EEF-CVE-2025-4754 (GHSA-f7gq-h8jv-h3cq, CVE-2025-4754)"

    assert EefFeed.record_findings(@live_shape, %{"ash_authentication_phoenix" => "2.10.0"}) == []
    assert EefFeed.record_findings(@live_shape, %{"unrelated" => "1.0.0"}) == []
  end

  describe "check/2 against a fake feed" do
    setup do
      cache = Path.join(System.tmp_dir!(), "dep_guard_cache_#{System.unique_integer([:positive])}")
      File.mkdir_p!(cache)
      on_exit(fn -> File.rm_rf(cache) end)
      {:ok, cache: cache}
    end

    test "fetches the index and records, and reports a match", %{cache: cache} do
      index = JSON.encode!([%{"id" => "EEF-1", "modified" => "2026-01-01T00:00:00Z"}])
      record = record(range([%{"introduced" => "0"}, %{"fixed" => "4.5.1"}])) |> Map.put("id", "EEF-1")

      server = DepGuard.TestHttp.start(%{"/all.json" => index, "/EEF-1.json" => JSON.encode!(record)})
      on_exit(fn -> DepGuard.TestHttp.stop(server) end)

      assert %{status: :ok, stats: %{records: 1, fetched: 1}} =
               EefFeed.check(%{"esaml" => "4.5.0"}, base_url: server.url, cache_dir: cache)

      result = EefFeed.check(%{"esaml" => "4.5.0"}, base_url: server.url, cache_dir: cache)
      assert [%{id: "EEF-1"}] = result.findings
      assert result.stats.cached >= 1
    end

    test "an empty index is an operational error, not a pass", %{cache: cache} do
      server = DepGuard.TestHttp.start(%{"/all.json" => "[]"})
      on_exit(fn -> DepGuard.TestHttp.stop(server) end)

      assert %{status: :error, findings: [%{kind: :operational}]} =
               EefFeed.check(%{"esaml" => "1.0.0"}, base_url: server.url, cache_dir: cache)
    end

    test "an index entry without an id is an operational error", %{cache: cache} do
      server = DepGuard.TestHttp.start(%{"/all.json" => ~s([{"modified":"x"}])})
      on_exit(fn -> DepGuard.TestHttp.stop(server) end)

      assert %{status: :error} = EefFeed.check(%{"esaml" => "1.0.0"}, base_url: server.url, cache_dir: cache)
    end

    test "a record fetch failure is operational", %{cache: cache} do
      index = JSON.encode!([%{"id" => "EEF-404"}])
      server = DepGuard.TestHttp.start(%{"/all.json" => index})
      on_exit(fn -> DepGuard.TestHttp.stop(server) end)

      result = EefFeed.check(%{"esaml" => "1.0.0"}, base_url: server.url, cache_dir: cache)
      assert result.status == :error
      assert [%{kind: :operational, message: message}] = result.findings
      assert message =~ "could not be fetched"
    end

    test "a malformed record is operational, not a crash", %{cache: cache} do
      index = JSON.encode!([%{"id" => "EEF-BAD"}])

      bad =
        JSON.encode!(%{
          "id" => "EEF-BAD",
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "esaml"},
              "ranges" => [%{"type" => "SEMVER", "events" => nil}]
            }
          ]
        })

      server = DepGuard.TestHttp.start(%{"/all.json" => index, "/EEF-BAD.json" => bad})
      on_exit(fn -> DepGuard.TestHttp.stop(server) end)

      assert %{status: :error, findings: [%{kind: :operational, message: message}]} =
               EefFeed.check(%{"esaml" => "1.0.0"}, base_url: server.url, cache_dir: cache)

      assert message =~ "EEF-BAD"
    end

    test "a project with no Hex packages does not fetch the feed" do
      assert %{status: :ok, findings: [], stats: %{records: 0}} = EefFeed.check(%{})
    end
  end
end
