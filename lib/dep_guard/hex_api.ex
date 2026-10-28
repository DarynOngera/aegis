defmodule DepGuard.HexApi do
  @moduledoc """
  Native retirements and security advisories from the Hex API.

  `GET https://hex.pm/api/packages/<name>` returns, for the package:

    * `retirements` - version => reason/message
    * `security_advisories` - id, aliases, CVSS, `affected` requirement strings

  One request per locked package, cached by URL. Private packages are reported
  as `uncovered`: the public API cannot tell us whether they are vulnerable.
  """

  alias DepGuard.{Fetch, Finding}

  @default_base "https://hex.pm/api"
  @concurrency 6

  @type package :: %{name: String.t(), version: String.t(), repo: String.t() | nil, app: String.t()}
  @type result :: %{
          name: String.t(),
          status: :ok | :error | :uncovered | :skipped,
          findings: [Finding.t()],
          notices: [Finding.t()],
          stats: map()
        }

  @spec check([package()], keyword()) :: result()
  def check(packages, opts \\ []) do
    started = System.monotonic_time(:millisecond)

    acc =
      packages
      |> Enum.sort_by(& &1.name)
      |> Task.async_stream(&audit_package(&1, opts),
        max_concurrency: Keyword.get(opts, :concurrency, @concurrency),
        timeout: 90_000,
        on_timeout: :kill_task,
        ordered: true
      )
      |> Enum.reduce(
        %{findings: [], statuses: [], stats: %{packages: length(packages), requests: 0, cached: 0, uncovered: 0}},
        fn
          {:ok, {status, findings, requests, cached}}, acc ->
            collect(acc, status, findings, requests, cached)

          {:exit, reason}, acc ->
            finding = operational(nil, nil, "hex_api: request aborted (#{inspect(reason)})")
            collect(acc, :error, [finding], 1, 0)
        end
      )

    %{
      name: "hex_api",
      status: status(acc.statuses),
      findings: acc.findings,
      notices: [],
      stats: Map.put(acc.stats, :duration_ms, System.monotonic_time(:millisecond) - started)
    }
  end

  defp collect(acc, status, findings, requests, cached) do
    %{
      acc
      | findings: acc.findings ++ List.wrap(findings),
        statuses: [status | acc.statuses],
        stats: add_stats(acc.stats, requests, cached, if(status == :uncovered, do: 1, else: 0))
    }
  end

  defp audit_package(%{name: name, version: version, repo: repo}, opts) do
    if repo in [nil, "hexpm"] do
      fetch_package(name, version, opts)
    else
      finding =
        operational(
          name,
          version,
          "hex_api: #{name} comes from private Hex repo #{inspect(repo)}; the public advisory " <>
            "API cannot cover it. Treat this dependency as unchecked."
        )

      {:uncovered, finding, 0, 0}
    end
  end

  defp fetch_package(name, version, opts) do
    url = base_url(opts) <> "/packages/" <> URI.encode_www_form(name)

    fetch_opts =
      opts
      |> Keyword.take([:cache_dir, :offline, :ttl])
      |> Keyword.put(:headers, auth_headers(opts))

    case Fetch.get_json(url, fetch_opts) do
      {:ok, body, source} ->
        {requests, cached} = if source == :network, do: {1, 0}, else: {0, 1}

        case package_findings(name, version, body) do
          {:ok, findings} -> {:ok, findings, requests, cached}
          {:error, findings} -> {:error, findings, requests, cached}
        end

      {:error, message} ->
        kind = if String.contains?(message, "HTTP 404"), do: :uncovered, else: :error
        finding = operational(name, version, "hex_api: #{message}")

        case kind do
          :uncovered -> {:uncovered, finding, 0, 0}
          :error -> {:error, finding, 1, 0}
        end
    end
  end

  defp package_findings(name, version, body) when is_map(body) do
    retirements = retirement_findings(name, version, body)
    advisories = advisory_findings(name, version, body)
    findings = retirements ++ advisories

    if Enum.any?(findings, &(&1.kind == :operational)) do
      {:error, findings}
    else
      {:ok, findings}
    end
  end

  defp package_findings(name, version, _body) do
    {:error, [operational(name, version, "hex_api: response for #{name} is not a JSON object")]}
  end

  defp retirement_findings(name, version, body) do
    case Map.get(body, "retirements") do
      nil ->
        []

      retirements when is_map(retirements) ->
        retirement = Map.get(retirements, version)

        if is_nil(retirement) do
          []
        else
          retirement_finding(name, version, retirement)
        end

      other ->
        [
          operational(
            name,
            version,
            "hex_api: retirements for #{name} have an unexpected shape (#{inspect(other)})"
          )
        ]
    end
  end

  defp retirement_finding(name, version, retirement) when is_map(retirement) do
    message = string_or(retirement["message"], "no reason given")
    reason = string_or(retirement["reason"], "other")

    [
      Finding.new(
        id: "retirement:#{name}@#{version}",
        check: :retirements,
        kind: :security,
        severity: :high,
        package: name,
        version: version,
        path: "mix.lock",
        message: "#{name} #{version} is retired: #{message} (reason: #{reason})",
        remediation: "upgrade #{name} to a maintained version"
      )
    ]
  end

  defp retirement_finding(name, version, other) do
    [
      operational(
        name,
        version,
        "hex_api: retirement data for #{name} #{version} has an unexpected shape (#{inspect(other)})"
      )
    ]
  end

  defp advisory_findings(name, version, body) do
    body
    |> Map.get("security_advisories", [])
    |> List.wrap()
    |> Enum.flat_map(&advisory_finding(name, version, &1))
  end

  defp advisory_finding(name, version, advisory) when is_map(advisory) do
    cond do
      Map.get(advisory, "withdrawn_at") ->
        []

      not is_binary(Map.get(advisory, "id")) ->
        [operational(name, version, "hex_api: advisory for #{name} has no id")]

      true ->
        case affected?(version, advisory) do
          true -> [advisory_to_finding(name, version, advisory)]
          false -> []
          :unevaluable -> [unevaluable(name, version, advisory)]
        end
    end
  end

  defp advisory_finding(name, version, _advisory) do
    [operational(name, version, "hex_api: advisory for #{name} is not an object")]
  end

  defp unevaluable(name, version, advisory) do
    operational(
      name,
      version,
      "hex_api: #{advisory["id"]} lists #{name} but its affected range could not be evaluated " <>
        "(#{inspect(advisory["affected"])})"
    )
  end

  defp affected?(version, advisory) do
    requirements = List.wrap(advisory["affected"])

    if requirements == [] do
      :unevaluable
    else
      Enum.reduce_while(requirements, false, fn requirement, _acc ->
        case matches?(version, requirement) do
          true -> {:halt, true}
          false -> {:cont, false}
          :error -> {:halt, :unevaluable}
        end
      end)
    end
  end

  defp matches?(version, requirement) when is_binary(requirement) do
    Version.match?(version, requirement, allow_pre: true)
  rescue
    _ -> :error
  end

  defp matches?(_version, _requirement), do: :error

  defp advisory_to_finding(name, version, advisory) do
    id = advisory["id"]
    aliases = advisory |> Map.get("aliases") |> binary_list()
    requirements = advisory |> Map.get("affected") |> binary_list() |> Enum.join(", ")
    requirements = if requirements == "", do: "the affected range", else: requirements
    summary = string_or(advisory["summary"], "security advisory")

    Finding.new(
      id: id,
      check: :advisories,
      kind: :security,
      severity: severity(advisory),
      package: name,
      version: version,
      path: "mix.lock",
      message: "#{name} #{version} is affected by #{id}: #{summary}",
      remediation: "upgrade #{name} outside #{requirements}",
      aliases: aliases,
      sources: ["hex_api"]
    )
  end

  defp severity(advisory) do
    if is_binary(advisory["cvss_rating"]) do
      Finding.severity_from_string(advisory["cvss_rating"])
    else
      cvss_severity(advisory["cvss_score"])
    end
  end

  defp cvss_severity(score) when is_number(score) and score >= 9.0, do: :critical
  defp cvss_severity(score) when is_number(score) and score >= 7.0, do: :high
  defp cvss_severity(score) when is_number(score) and score >= 4.0, do: :medium
  defp cvss_severity(score) when is_number(score), do: :low
  defp cvss_severity(_score), do: :unknown

  defp operational(name, version, message) do
    Finding.new(
      check: :advisories,
      kind: :operational,
      severity: :high,
      package: name,
      version: version,
      path: "mix.lock",
      message: message
    )
  end

  defp status(statuses) do
    cond do
      :error in statuses -> :error
      :uncovered in statuses -> :uncovered
      true -> :ok
    end
  end

  defp add_stats(stats, requests, cached, uncovered) do
    %{
      stats
      | requests: stats.requests + requests,
        cached: stats.cached + cached,
        uncovered: stats.uncovered + uncovered
    }
  end

  defp base_url(opts) do
    opts |> Keyword.get(:base_url, @default_base) |> String.trim_trailing("/")
  end

  defp auth_headers(opts) do
    case Keyword.get(opts, :api_key) || System.get_env("HEX_API_KEY") do
      nil -> []
      "" -> []
      key -> [{"authorization", "Bearer " <> key}]
    end
  end

  defp string_or(value, _default) when is_binary(value), do: value
  defp string_or(_value, default), do: default

  defp binary_list(list) when is_list(list), do: Enum.filter(list, &is_binary/1)
  defp binary_list(_other), do: []
end
