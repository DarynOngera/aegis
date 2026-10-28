defmodule DepGuard.Fetch do
  @moduledoc """
  Cached JSON GET with bounded retries.

  A cache hit is used when the entry is younger than `:ttl` (default one hour).
  In offline mode `:cache` must be set and any cached entry is accepted, whatever
  its age; a missing entry is an error, never an empty result.
  """

  alias DepGuard.Http

  @default_ttl 3_600
  @attempts 3
  @retry_statuses [429, 500, 502, 503, 504]

  @spec get_json(String.t(), keyword()) ::
          {:ok, term(), :cache | :network} | {:error, String.t()}
  def get_json(url, opts \\ []) do
    dir = Keyword.get(opts, :cache_dir) || default_cache_dir()
    ttl = Keyword.get(opts, :ttl, @default_ttl)
    offline = Keyword.get(opts, :offline, false)
    headers = Keyword.get(opts, :headers, [])

    case read_cache(dir, url, ttl, offline) do
      {:ok, value} ->
        {:ok, value, :cache}

      :stale_or_missing when offline ->
        {:error, "offline and no cached response for #{url} (cache: #{dir})"}

      :stale_or_missing ->
        with {:ok, value} <- request_with_retries(url, headers, 1) do
          write_cache(dir, url, value)
          {:ok, value, :network}
        end
    end
  end

  @doc "Cache directory used when `--cache-dir` is not given."
  @spec default_cache_dir() :: Path.t()
  def default_cache_dir do
    base = System.get_env("XDG_CACHE_HOME") || Path.join(System.user_home!(), ".cache")
    Path.join(base, "dep_guard")
  end

  defp request_with_retries(url, headers, attempt) do
    case Http.get_json(url, headers) do
      {:ok, value} ->
        {:ok, value}

      {:error, %{status: status, message: message}} ->
        if attempt < @attempts and retry?(status) do
          Process.sleep(250 * attempt)
          request_with_retries(url, headers, attempt + 1)
        else
          {:error, message}
        end
    end
  end

  defp retry?(nil), do: true
  defp retry?(status), do: status in @retry_statuses

  defp read_cache(dir, url, ttl, offline) do
    with {:ok, source} <- File.read(cache_path(dir, url)),
         {:ok, %{"stored_at" => stored, "value" => value}} <- JSON.decode(source) do
      if offline or fresh?(stored, ttl), do: {:ok, value}, else: :stale_or_missing
    else
      _ -> :stale_or_missing
    end
  end

  defp fresh?(stored_at, ttl) when is_integer(stored_at) do
    System.os_time(:second) - stored_at <= ttl
  end

  defp fresh?(_stored_at, _ttl), do: false

  defp write_cache(dir, url, value) do
    File.mkdir_p!(dir)
    path = cache_path(dir, url)
    payload = JSON.encode!(%{"stored_at" => System.os_time(:second), "value" => value})
    File.write!(path, payload)
  rescue
    # A read-only or missing cache directory must not fail the scan.
    _ -> :ok
  end

  defp cache_path(dir, url) do
    key = :crypto.hash(:sha256, url) |> Base.encode16(case: :lower)
    Path.join(dir, key <> ".json")
  end
end
