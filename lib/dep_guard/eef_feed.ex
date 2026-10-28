defmodule DepGuard.EefFeed do
  @moduledoc """
  Cross-checks the lockfile against the EEF CNA's public OSV feed
  (https://cna.erlef.org/osv). No token needed.

  Layout: `<base>/all.json` is an index of `%{"id" => ..., "modified" => ...}`
  and each record lives at `<base>/<id>.json` in the OSV schema.

  Fails closed: an unreachable feed, a record that cannot be read, a record with
  no `affected` entries, or an affected range that cannot be evaluated is an
  `:operational` finding, never a silent pass. Withdrawn records produce a
  notice and are skipped.
  """

  alias DepGuard.{Fetch, Finding}

  @default_base "https://cna.erlef.org/osv"

  @type result :: %{
          name: String.t(),
          status: :ok | :error,
          findings: [Finding.t()],
          notices: [Finding.t()],
          stats: map()
        }

  @spec check(%{optional(String.t()) => String.t()}, keyword()) :: result()
  def check(hex_versions, opts \\ []) do
    started = System.monotonic_time(:millisecond)

    if map_size(hex_versions) == 0 do
      empty_result(started)
    else
      base = base_url(opts)
      fetch_opts = Keyword.take(opts, [:cache_dir, :offline, :ttl, :concurrency])

      case Fetch.get_json("#{base}/all.json", fetch_opts) do
        {:ok, index, _source} when is_list(index) ->
          audit_index(base, index, hex_versions, fetch_opts, started)

        {:ok, _other, _source} ->
          error_result("#{base}/all.json is not a JSON list. Refusing to treat that as no vulnerabilities.", started)

        {:error, message} ->
          error_result(message, started)
      end
    end
  end

  defp empty_result(started) do
    %{
      name: "eef",
      status: :ok,
      findings: [],
      notices: [],
      stats: %{
        records: 0,
        fetched: 0,
        cached: 0,
        errors: 0,
        duration_ms: System.monotonic_time(:millisecond) - started
      }
    }
  end

  defp audit_index(base, index, hex_versions, fetch_opts, started) do
    ids =
      for %{"id" => id} <- index, is_binary(id) and id != "" do
        id
      end

    cond do
      index == [] ->
        error_result("#{base}/all.json is an empty list. Refusing to treat that as no vulnerabilities.", started)

      length(ids) != length(index) ->
        error_result(
          "#{base}/all.json has #{length(index)} entries but only #{length(ids)} with an id; " <>
            "the index shape changed.",
          started
        )

      ids == [] ->
        error_result("#{base}/all.json has #{length(index)} entries but none with an id.", started)

      true ->
        unique = Enum.uniq(ids)

        results =
          unique
          |> Task.async_stream(&fetch_record(base, &1, fetch_opts),
            max_concurrency: Keyword.get(fetch_opts, :concurrency, 8),
            timeout: 60_000,
            on_timeout: :kill_task,
            ordered: true
          )
          |> Enum.map(fn
            {:ok, result} -> result
            {:exit, reason} -> {:error, nil, "record fetch aborted (#{inspect(reason)})"}
          end)

        summarize(results, hex_versions, length(unique), started)
    end
  end

  defp fetch_record(base, id, fetch_opts) do
    case Fetch.get_json("#{base}/#{id}.json", fetch_opts) do
      {:ok, %{} = record, source} -> {:ok, Map.put_new(record, "id", id), source}
      {:ok, _other, _source} -> {:error, id, "record is not a JSON object"}
      {:error, message} -> {:error, id, message}
    end
  end

  defp summarize(results, hex_versions, total, started) do
    {fetched, errors} = Enum.split_with(results, &match?({:ok, _, _}, &1))

    stats = %{
      records: total,
      fetched: length(fetched),
      cached: Enum.count(fetched, &match?({:ok, _, :cache}, &1)),
      errors: length(errors),
      duration_ms: System.monotonic_time(:millisecond) - started
    }

    fetch_findings =
      case errors do
        [] ->
          []

        list ->
          messages = Enum.map(list, fn {:error, id, message} -> "#{id || "record"}: #{message}" end)

          [
            Finding.new(
              check: :eef,
              kind: :operational,
              severity: :high,
              path: "mix.lock",
              message:
                "eef: #{length(messages)} record(s) could not be fetched or read, so this check is incomplete. " <>
                  "First errors:\n" <> Enum.map_join(Enum.take(messages, 3), "\n", &("  " <> &1))
            )
          ]
      end

    {findings, notices} =
      fetched
      |> Enum.flat_map(fn {:ok, record, _source} -> safe_record_findings(record, hex_versions) end)
      |> Enum.split_with(&(&1.kind != :notice))

    all_findings = fetch_findings ++ findings

    %{
      name: "eef",
      status: if(Enum.any?(all_findings, &(&1.kind == :operational)), do: :error, else: :ok),
      findings: all_findings,
      notices: notices,
      stats: stats
    }
  end

  # A malformed record must never abort the whole scan. If the evaluator raises
  # on a shape we did not anticipate, turn it into an operational finding.
  defp safe_record_findings(record, versions) do
    record_findings(record, versions)
  rescue
    exception ->
      id = if is_binary(record["id"]), do: record["id"], else: nil

      [
        operational(
          nil,
          nil,
          "eef: #{id || "record"} could not be evaluated (#{Exception.message(exception)}); review it manually"
        )
      ]
  end

  @doc """
  Findings for one OSV record against `%{package => locked_version}`. Pure;
  no network.
  """
  @spec record_findings(map(), %{optional(String.t()) => String.t()}) :: [Finding.t()]
  def record_findings(record, versions) when is_map(record) do
    id = record["id"]

    cond do
      not is_binary(id) ->
        [operational(nil, nil, "eef: record without an id")]

      Map.get(record, "withdrawn") ->
        [notice(id, "eef: #{id} was withdrawn by the publisher; not applied")]

      not is_list(record["affected"]) or record["affected"] == [] ->
        [operational(nil, nil, "eef: #{id} has no affected entries; refusing to skip it silently")]

      true ->
        Enum.flat_map(List.wrap(record["affected"]), &affected_findings(id, record, &1, versions))
    end
  end

  defp affected_findings(id, record, %{"package" => %{"name" => name} = pkg} = affected, versions)
       when is_binary(name) do
    with true <- hex?(pkg),
         {:ok, version} <- Map.fetch(versions, name) do
      case status(affected, version) do
        :affected ->
          [affected_finding(id, record, name, version)]

        :unknown ->
          [
            operational(
              name,
              version,
              "eef: #{id} lists #{name} #{version} but the affected range could not be evaluated; " <>
                "review the advisory manually"
            )
          ]

        :unaffected ->
          []
      end
    else
      _ -> []
    end
  end

  defp affected_findings(_id, _record, _affected, _versions), do: []

  defp affected_finding(id, record, name, version) do
    aliases = binary_list(record["aliases"])

    Finding.new(
      id: id,
      check: :eef,
      kind: :security,
      severity: severity(record),
      package: name,
      version: version,
      path: "mix.lock",
      message: "#{name} #{version} is affected by #{id}#{alias_suffix(aliases)}",
      remediation: remediation(record),
      aliases: aliases,
      sources: ["eef"]
    )
  end

  defp alias_suffix([]), do: ""
  defp alias_suffix(aliases), do: " (#{Enum.join(aliases, ", ")})"

  defp remediation(record) do
    fixed =
      for %{"ranges" => ranges} <- List.wrap(record["affected"]),
          is_list(ranges),
          %{"events" => events} <- ranges,
          is_list(events),
          %{"fixed" => version} <- events,
          is_binary(version),
          do: version

    case Enum.uniq(fixed) do
      [] -> "upgrade to a version outside the affected range"
      versions -> "upgrade to #{Enum.join(versions, " or ")} or later"
    end
  end

  defp severity(record) do
    case record do
      %{"database_specific" => %{"severity" => value}} -> Finding.severity_from_string(value)
      _other -> :high
    end
  end

  defp operational(package, version, message) do
    Finding.new(
      check: :eef,
      kind: :operational,
      severity: :high,
      package: package,
      version: version,
      path: "mix.lock",
      message: message
    )
  end

  defp notice(id, message) do
    Finding.new(id: id, check: :eef, kind: :notice, severity: :info, path: "mix.lock", message: message)
  end

  defp hex?(pkg) do
    case Map.get(pkg, "ecosystem") do
      value when is_binary(value) -> String.starts_with?(String.downcase(value), "hex")
      _other -> false
    end
  end

  @doc false
  def status(affected, version) when is_map(affected) do
    listed = binary_list(affected["versions"])

    case comparable_ranges(affected["ranges"]) do
      :error ->
        :unknown

      {:ok, ranges} ->
        verdicts = Enum.map(ranges, &range_verdict(&1, version))

        cond do
          version in listed -> :affected
          true in verdicts -> :affected
          listed == [] and ranges == [] -> :unknown
          :unknown in verdicts -> :unknown
          true -> :unaffected
        end
    end
  end

  def status(_affected, _version), do: :unknown

  # Unknown range types (for example GIT) are irrelevant to Hex versions and are
  # ignored. A SEMVER/ECOSYSTEM range with unreadable events makes the result
  # unknown, which the caller turns into an operational finding.
  defp comparable_ranges(nil), do: {:ok, []}

  defp comparable_ranges(ranges) when is_list(ranges) do
    Enum.reduce_while(ranges, {:ok, []}, fn
      %{"type" => type, "events" => events}, {:ok, acc} when type in ["SEMVER", "ECOSYSTEM"] ->
        if is_list(events) do
          {:cont, {:ok, [events | acc]}}
        else
          {:halt, :error}
        end

      %{"type" => type}, _acc when type in ["SEMVER", "ECOSYSTEM"] ->
        {:halt, :error}

      _other, acc ->
        {:cont, acc}
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      :error -> :error
    end
  end

  defp comparable_ranges(_other), do: :error

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

  defp parse_events(events) when is_list(events) do
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

  defp parse_events(_other), do: :error

  defp parse_version("0"), do: Version.parse("0.0.0")
  defp parse_version(value) when is_binary(value), do: Version.parse(value)
  defp parse_version(_), do: :error

  defp binary_list(list) when is_list(list), do: Enum.filter(list, &is_binary/1)
  defp binary_list(_other), do: []

  defp error_result(message, started) do
    %{
      name: "eef",
      status: :error,
      findings: [operational(nil, nil, "eef: " <> message)],
      notices: [],
      stats: %{records: 0, fetched: 0, cached: 0, errors: 1, duration_ms: System.monotonic_time(:millisecond) - started}
    }
  end

  defp base_url(opts) do
    opts |> Keyword.get(:base_url, @default_base) |> String.trim_trailing("/")
  end
end
