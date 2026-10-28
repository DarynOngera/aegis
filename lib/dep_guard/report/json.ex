defmodule DepGuard.Report.JSON do
  @moduledoc "Canonical JSON rendering. One scan produces one object of this shape."

  alias DepGuard.Report

  @spec render(Report.t()) :: String.t()
  def render(%Report{} = report) do
    JSON.encode!(Report.to_map(report)) <> "\n"
  end

  @doc "Reads a previously written JSON report (used by `dep_guard render`)."
  @spec load(Path.t()) :: {:ok, Report.t()} | {:error, String.t()}
  def load(path) do
    with {:ok, source} <- File.read(path),
         {:ok, map} <- decode(path, source),
         {:ok, report} <- from_map(map) do
      {:ok, report}
    else
      {:error, message} -> {:error, message}
    end
  end

  defp decode(path, source) do
    case JSON.decode(source) do
      {:ok, map} when is_map(map) -> {:ok, map}
      {:ok, _other} -> {:error, "#{path}: report must be a JSON object"}
      {:error, reason} -> {:error, "#{path}: invalid JSON (#{inspect(reason)})"}
    end
  end

  defp from_map(map) do
    report = %Report{
      schema_version: map["schema_version"] || "1.0",
      tool: atomize(map["tool"]),
      run: atomize(map["run"]),
      project: atomize(map["project"]),
      policy: atomize(map["policy"]),
      inputs: atomize(map["inputs"]),
      sources: Enum.map(map["sources"] || [], &atomize/1),
      findings: Enum.map(map["findings"] || [], &finding/1),
      notices: Enum.map(map["notices"] || [], &finding/1),
      summary: atomize(map["summary"])
    }

    {:ok, report}
  end

  defp atomize(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {atom(key), value} end)
  end

  defp atomize(other), do: other

  # Keys written by this tool exist as atoms; a key from a newer report is kept
  # as a string rather than failing the whole map.
  defp atom(key) when is_binary(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> key
  end

  defp atom(key), do: key

  defp finding(map) when is_map(map) do
    %DepGuard.Finding{
      id: map["id"],
      check: check(map["check"]),
      kind: kind(map["kind"]),
      severity: DepGuard.Finding.severity_from_string(map["severity"]),
      message: map["message"] || "",
      package: map["package"],
      version: map["version"],
      remediation: map["remediation"],
      path: map["path"],
      waived: waiver(map["waiver"]),
      aliases: map["aliases"] || [],
      sources: map["sources"] || []
    }
  end

  defp check(value) when is_binary(value) do
    String.to_existing_atom(value)
  rescue
    ArgumentError -> value
  end

  defp check(value), do: value

  defp kind(value) when is_binary(value) do
    case value do
      "security" -> :security
      "integrity" -> :integrity
      "policy" -> :policy
      "operational" -> :operational
      "notice" -> :notice
      _ -> :security
    end
  end

  defp kind(value), do: value

  defp waiver(%{"reason" => reason, "expires" => expires}), do: %{reason: reason, expires: expires}
  defp waiver(_other), do: nil
end
