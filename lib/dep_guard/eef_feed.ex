defmodule DepGuard.EefFeed do
  @moduledoc """
  Cross-checks the lockfile against the EEF CNA's public OSV feed
  (https://cna.erlef.org/osv). No token needed.

  Layout assumed (OSV convention): `<base>/all.json` is an index of
  `%{"id" => ..., "modified" => ...}` and each record lives at `<base>/<id>.json`
  in the standard OSV schema (`affected[].package`, `ranges`, `versions`).
  The index layout is confirmed; the per-record URL is the OSV convention and
  has not been verified. Override with `eef_osv_base:` if it differs.

  Fails closed: an unreachable feed, unreadable records, or an affected range that
  cannot be evaluated is reported as a problem, never silently skipped.
  """

  alias DepGuard.Http

  @default_base "https://cna.erlef.org/osv"

  @spec check(%{optional(String.t()) => String.t()}, [String.t()], keyword()) :: [String.t()]
  def check(hex_versions, ignored_ids, opts \\ []) do
    base = Keyword.get(opts, :base_url, @default_base)

    case Http.get_json("#{base}/all.json") do
      {:ok, [_ | _] = index} ->
        index
        |> Enum.flat_map(fn
          %{"id" => id} when is_binary(id) -> [id]
          _ -> []
        end)
        |> Task.async_stream(&fetch_record(base, &1),
          max_concurrency: 8,
          timeout: 30_000,
          on_timeout: :kill_task,
          ordered: false
        )
        |> Enum.map(fn
          {:ok, {:ok, record}} -> {:ok, record}
          {:ok, {:error, message}} -> {:error, message}
          {:exit, reason} -> {:error, "record fetch aborted (#{inspect(reason)})"}
        end)
        |> summarize(hex_versions, ignored_ids)

      {:ok, _empty_or_wrong} ->
        ["EEF feed: #{base}/all.json is empty or not a list. Refusing to treat that as 'no vulnerabilities'."]

      {:error, message} ->
        ["EEF feed: #{message}"]
    end
  end

  defp fetch_record(base, id) do
    case Http.get_json("#{base}/#{id}.json") do
      {:ok, %{} = record} -> {:ok, Map.put_new(record, "id", id)}
      {:ok, _other} -> {:error, "#{id}: record is not a JSON object"}
      {:error, message} -> {:error, message}
    end
  end

  defp summarize(results, hex_versions, ignored_ids) do
    {oks, errors} = Enum.split_with(results, &match?({:ok, _}, &1))

    fetch_problems =
      case Enum.map(errors, &elem(&1, 1)) do
        [] ->
          []

        messages ->
          [
            "EEF feed: #{length(messages)} record(s) could not be fetched or read, so this check is " <>
              "incomplete. First errors:\n" <>
              Enum.map_join(Enum.take(messages, 3), "\n", &("    " <> &1))
          ]
      end

    fetch_problems ++
      Enum.flat_map(oks, fn {:ok, record} -> record_problems(record, hex_versions, ignored_ids) end)
  end

  defp record_problems(record, hex_versions, ignored_ids) do
    ids = [record["id"] | List.wrap(record["aliases"])]

    if Enum.any?(ids, &(&1 in ignored_ids)), do: [], else: matches(record, hex_versions)
  end

  @doc """
  Problems for one OSV record against `%{package => locked_version}`.
  Pure function; no network.
  """
  @spec matches(map(), %{optional(String.t()) => String.t()}) :: [String.t()]
  def matches(%{"id" => id} = record, versions) do
    aliases =
      case List.wrap(record["aliases"]) do
        [] -> ""
        list -> " (#{Enum.join(list, ", ")})"
      end

    record["affected"]
    |> List.wrap()
    |> Enum.flat_map(fn
      %{"package" => %{"name" => name} = pkg} = affected ->
        with true <- hex?(pkg), {:ok, version} <- Map.fetch(versions, name) do
          case status(affected, version) do
            :affected ->
              ["#{name} #{version} is affected by #{id}#{aliases}"]

            :unknown ->
              [
                "#{name} #{version}: #{id}#{aliases} lists this package but the affected range could not be evaluated; review manually"
              ]

            :unaffected ->
              []
          end
        else
          _ -> []
        end

      _ ->
        []
    end)
  end

  defp hex?(pkg) do
    pkg |> Map.get("ecosystem", "") |> to_string() |> String.downcase() |> String.starts_with?("hex")
  end

  defp status(affected, version) do
    listed = List.wrap(affected["versions"])

    ranges =
      for %{"type" => type, "events" => events} <- List.wrap(affected["ranges"]),
          type in ["SEMVER", "ECOSYSTEM"],
          do: events

    verdicts = Enum.map(ranges, &range_verdict(&1, version))

    cond do
      version in listed -> :affected
      true in verdicts -> :affected
      listed == [] and ranges == [] -> :unknown
      :unknown in verdicts -> :unknown
      true -> :unaffected
    end
  end

  # OSV range evaluation: sort events by version, walk them, and flip state on
  # `introduced` (>= v), `fixed` (>= v) and `last_affected` (> v).
  defp range_verdict(events, version) do
    with {:ok, v} <- Version.parse(version),
         {:ok, parsed} <- parse_events(events) do
      parsed
      |> Enum.sort(fn {_, a}, {_, b} -> Version.compare(a, b) != :gt end)
      |> Enum.reduce(false, fn
        {"introduced", e}, acc -> if Version.compare(v, e) != :lt, do: true, else: acc
        {"fixed", e}, acc -> if Version.compare(v, e) != :lt, do: false, else: acc
        {"last_affected", e}, acc -> if Version.compare(v, e) == :gt, do: false, else: acc
      end)
    else
      _ -> :unknown
    end
  end

  defp parse_events(events) do
    parsed =
      Enum.map(events, fn event ->
        with [{kind, value}] <- Enum.to_list(event),
             true <- kind in ~w(introduced fixed last_affected),
             {:ok, version} <- parse_version(value) do
          {kind, version}
        else
          _ -> :bad
        end
      end)

    if :bad in parsed, do: :error, else: {:ok, parsed}
  end

  defp parse_version("0"), do: Version.parse("0.0.0")
  defp parse_version(value) when is_binary(value), do: Version.parse(value)
  defp parse_version(_), do: :error
end
