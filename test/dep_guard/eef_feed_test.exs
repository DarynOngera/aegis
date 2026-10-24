defmodule DepGuard.EefFeedTest do
  use ExUnit.Case, async: true

  alias DepGuard.EefFeed

  # Standard OSV schema. The per-record URL layout of the EEF feed is unverified,
  # but the matching logic only depends on the OSV record format.
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

    assert [message] = EefFeed.matches(r, %{"esaml" => "4.5.0"})
    assert message =~ "esaml 4.5.0 is affected by EEF-CVE-2026-0001 (CVE-2026-0001)"

    assert EefFeed.matches(r, %{"esaml" => "4.5.1"}) == []
    assert EefFeed.matches(r, %{"esaml" => "5.0.0"}) == []
  end

  test "introduced lower bound is respected" do
    r = record(range([%{"introduced" => "2.0.0"}, %{"fixed" => "2.3.0"}]))
    assert EefFeed.matches(r, %{"esaml" => "1.9.0"}) == []
    assert [_] = EefFeed.matches(r, %{"esaml" => "2.1.0"})
  end

  test "last_affected is inclusive" do
    r = record(range([%{"introduced" => "0"}, %{"last_affected" => "1.2.0"}]))
    assert [_] = EefFeed.matches(r, %{"esaml" => "1.2.0"})
    assert EefFeed.matches(r, %{"esaml" => "1.2.1"}) == []
  end

  test "explicit versions list is honoured" do
    r = record(%{"versions" => ["1.0.0", "1.0.1"]})
    assert [_] = EefFeed.matches(r, %{"esaml" => "1.0.1"})
    assert EefFeed.matches(r, %{"esaml" => "1.0.2"}) == []
  end

  test "packages not in the lock, or from other ecosystems, are ignored" do
    r = record(range([%{"introduced" => "0"}]))
    assert EefFeed.matches(r, %{"other" => "1.0.0"}) == []

    npm = put_in(r, ["affected", Access.at(0), "package", "ecosystem"], "npm")
    assert EefFeed.matches(npm, %{"esaml" => "1.0.0"}) == []
  end

  test "fails closed when the range cannot be evaluated" do
    no_info = record(%{})
    assert [message] = EefFeed.matches(no_info, %{"esaml" => "1.0.0"})
    assert message =~ "could not be evaluated"

    odd = record(range([%{"introduced" => "0"}, %{"fixed" => "not-a-version"}]))
    assert [message] = EefFeed.matches(odd, %{"esaml" => "1.0.0"})
    assert message =~ "could not be evaluated"
  end
end
