defmodule DepGuard.Report.SARIF do
  @moduledoc """
  SARIF 2.1.0 projection of a report, for GitHub code scanning.

  SARIF has no place for source coverage, so the report's source statuses and
  policy hashes are carried as run-level properties.
  """

  alias DepGuard.{Finding, Report}

  @schema "https://json.schemastore.org/sarif-2.1.0.json"

  @spec render(Report.t()) :: String.t()
  def render(%Report{} = report) do
    JSON.encode!(to_map(report)) <> "\n"
  end

  @spec to_map(Report.t()) :: map()
  def to_map(%Report{} = report) do
    %{
      "$schema" => @schema,
      version: "2.1.0",
      runs: [
        %{
          tool: %{driver: driver(report)},
          results: Enum.map(report.findings, &result/1),
          properties: %{
            project: report.project,
            policy: report.policy,
            inputs: report.inputs,
            sources: Enum.map(report.sources, &source/1),
            summary: report.summary
          }
        }
      ]
    }
  end

  defp driver(report) do
    %{
      name: "dep_guard",
      version: report.tool[:version] || "unknown",
      informationUri: "https://github.com/DarynOngera/dep_guard",
      rules: rules(report.findings)
    }
  end

  defp rules(findings) do
    findings
    |> Enum.map(& &1.check)
    |> Enum.uniq()
    |> Enum.map(fn check ->
      %{
        id: "dep_guard/#{check}",
        name: to_string(check),
        shortDescription: %{text: description(check)}
      }
    end)
  end

  defp description(:lockfile), do: "mix.lock integrity"
  defp description(:sources), do: "dependency source allowlist"
  defp description(:policy), do: "policy waiver hygiene"
  defp description(:mix_exs), do: "mix.exs ignore configuration"
  defp description(:lock_changes), do: "unsafe mix.lock changes"
  defp description(:retirements), do: "retired package versions"
  defp description(:advisories), do: "known security advisories"
  defp description(:eef), do: "EEF CNA advisories"
  defp description(:mix_audit), do: "mix_audit advisories (external)"
  defp description(_check), do: "dep_guard finding"

  defp result(%Finding{} = f) do
    base = %{
      ruleId: "dep_guard/#{f.check}",
      level: level(f),
      message: %{text: f.message},
      locations: locations(f),
      properties: %{
        kind: to_string(f.kind),
        severity: to_string(f.severity),
        package: f.package,
        version: f.version,
        aliases: f.aliases,
        sources: f.sources,
        waived: not is_nil(f.waived)
      }
    }

    # A waived finding must be marked suppressed, or code scanning keeps showing
    # it as an open alert even though the gate passed.
    case suppressions(f) do
      [] -> base
      list -> Map.put(base, :suppressions, list)
    end
  end

  defp suppressions(%Finding{waived: nil}), do: []

  defp suppressions(%Finding{waived: waiver}) do
    [
      %{
        kind: "external",
        status: "accepted",
        justification: "waived until #{Map.get(waiver, :expires)}: #{Map.get(waiver, :reason)}"
      }
    ]
  end

  defp level(%Finding{kind: :notice}), do: "note"
  defp level(%Finding{severity: s}) when s in [:critical, :high, :unknown], do: "error"
  defp level(%Finding{severity: :medium}), do: "warning"
  defp level(%Finding{severity: s}) when s in [:low, :info], do: "note"

  defp locations(%Finding{path: nil}), do: []

  defp locations(%Finding{path: path}) do
    [
      %{
        physicalLocation: %{
          artifactLocation: %{uri: path},
          region: %{startLine: 1}
        }
      }
    ]
  end

  defp source(source) do
    Map.update(source, :status, nil, &to_string/1)
  end
end
