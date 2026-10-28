defmodule DepGuard.Report.Human do
  @moduledoc "Human-readable projection of a report. Never triggers another scan."

  alias DepGuard.{Finding, Report}

  @spec render(Report.t(), keyword()) :: String.t()
  def render(%Report{} = report, opts \\ []) do
    threshold = Keyword.get(opts, :fail_on, :high)
    gate = Report.exit_code(report, threshold)

    [
      header(report),
      sources(report),
      findings(report.findings),
      notices(report.notices),
      summary(report, gate, threshold)
    ]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp header(report) do
    project = report.project[:root] || "."
    version = report.tool[:version] || "?"
    "dep_guard #{version} — #{project}"
  end

  defp sources(%Report{sources: []}), do: ""

  defp sources(report) do
    lines =
      Enum.map_join(report.sources, "\n", fn source ->
        "  #{source[:name]}: #{source[:status]}#{details(source)}"
      end)

    "sources:\n" <> lines
  end

  defp details(source) do
    source
    |> Enum.reject(fn {key, _} -> key in [:name, :status] end)
    |> Enum.sort_by(fn {key, _} -> to_string(key) end)
    |> Enum.map(fn {key, value} -> "#{key}=#{inline(value)}" end)
    |> case do
      [] -> ""
      parts -> " (" <> Enum.join(parts, ", ") <> ")"
    end
  end

  defp findings([]), do: ""

  defp findings(findings) do
    "findings:\n" <> Enum.map_join(findings, "\n\n", &finding/1)
  end

  defp notices([]), do: ""

  defp notices(notices) do
    "notices:\n" <> Enum.map_join(notices, "\n", &("  - " <> &1.message))
  end

  defp finding(%Finding{} = f) do
    title =
      [
        String.upcase(to_string(f.severity)),
        f.package && "#{f.package}#{f.version && " " <> f.version}",
        f.id || to_string(f.check)
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join("  ")

    [
      "  #{title}",
      indent(f.message),
      f.remediation && indent("fix: " <> f.remediation),
      f.waived && indent("waived until #{f.waived.expires}: #{f.waived.reason}"),
      sources_line(f)
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
  end

  defp sources_line(%Finding{sources: []}), do: nil
  defp sources_line(%Finding{sources: sources}), do: indent("sources: " <> Enum.join(sources, ", "))

  defp summary(report, 0, threshold) do
    "PASS — no unwaived findings at or above #{threshold}.#{counts(report)}"
  end

  defp summary(report, 2, _threshold) do
    "INCOMPLETE — the scan did not cover every source (operational error, or a source was skipped, " <>
      "unreachable or uncovered). Do not treat this run as clean.#{counts(report)}"
  end

  defp summary(report, 1, threshold) do
    "FAIL — unwaived findings at or above #{threshold}.#{counts(report)}"
  end

  defp counts(%Report{summary: summary}) do
    severities =
      [:critical, :high, :medium, :low, :info, :unknown]
      |> Enum.filter(fn key -> (summary[key] || 0) > 0 or key in [:high, :medium, :low] end)
      |> Enum.map_join(", ", fn key -> "#{summary[key] || 0} #{key}" end)

    " (#{severities}, #{summary[:waived] || 0} waived, #{summary[:notices] || 0} notices)"
  end

  defp indent(text) do
    text
    |> String.trim()
    |> String.split("\n")
    |> Enum.map_join("\n", &("    " <> &1))
  end

  defp inline(value) when is_binary(value), do: value
  defp inline(value), do: inspect(value)
end
