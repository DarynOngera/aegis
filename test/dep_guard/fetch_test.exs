defmodule DepGuard.FetchTest do
  use ExUnit.Case, async: true

  alias DepGuard.Fetch

  defp cache_dir do
    dir = Path.join(System.tmp_dir!(), "dep_guard_fetch_#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  test "fetches once and serves the next call from cache" do
    counter = :counters.new(1, [])
    dir = cache_dir()

    server =
      DepGuard.TestHttp.start(fn _path ->
        :counters.add(counter, 1, 1)
        {200, ~s({"ok":true})}
      end)

    on_exit(fn -> DepGuard.TestHttp.stop(server) end)

    assert {:ok, %{"ok" => true}, :network} = Fetch.get_json(server.url <> "/x", cache_dir: dir)
    assert {:ok, %{"ok" => true}, :cache} = Fetch.get_json(server.url <> "/x", cache_dir: dir)
    assert :counters.get(counter, 1) == 1
  end

  test "offline mode never touches the network" do
    dir = cache_dir()
    server = DepGuard.TestHttp.start(%{})
    on_exit(fn -> DepGuard.TestHttp.stop(server) end)

    assert {:error, message} = Fetch.get_json(server.url <> "/x", cache_dir: dir, offline: true)
    assert message =~ "offline"
  end

  test "retries a 5xx and then reports the error" do
    counter = :counters.new(1, [])
    dir = cache_dir()

    server =
      DepGuard.TestHttp.start(fn _path ->
        :counters.add(counter, 1, 1)
        {500, "{}"}
      end)

    on_exit(fn -> DepGuard.TestHttp.stop(server) end)

    assert {:error, message} = Fetch.get_json(server.url <> "/x", cache_dir: dir)
    assert message =~ "HTTP 500"
    assert :counters.get(counter, 1) == 3
  end

  test "a 404 is not retried" do
    counter = :counters.new(1, [])
    dir = cache_dir()

    server =
      DepGuard.TestHttp.start(fn _path ->
        :counters.add(counter, 1, 1)
        {404, "{}"}
      end)

    on_exit(fn -> DepGuard.TestHttp.stop(server) end)

    assert {:error, message} = Fetch.get_json(server.url <> "/x", cache_dir: dir)
    assert message =~ "HTTP 404"
    assert :counters.get(counter, 1) == 1
  end
end
