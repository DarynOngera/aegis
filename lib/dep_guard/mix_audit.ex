defmodule DepGuard.MixAudit do
  @moduledoc """
  Reads `mix deps.audit --format json` and normalises it into findings.

  The scanner never runs mix_audit itself. `mix_audit` remains an org-owned check;
  when its JSON is supplied, it is merged into the same report and deduplicated
  with the other sources by advisory ID/alias. If the file cannot be read or
  understood, the scan fails: a half-merged report is worse than no report.
  """

  alias DepGuard.Finding

  @spec load(Path.t()) :: {:ok, [Finding.t()]} | {:error, String.t()}
  def load(path) do
    with {:ok, source} <- File.read(path),
         {:ok, map} <- decode(path, source),
         {:ok, vulnerabilities} <- vulnerabilities(path, map) do
      normalise(path, vulnerabilities)
    else
      {:error, message} -> {:error, message}
    end
  end

  defp decode(path, source) do
    case JSON.decode(source) do
      {:ok, map} when is_map(map) -> {:ok, map}
      {:ok, _other} -> {:error, "#{path}: mix_audit report must be a JSON object"}
      {:error, reason} -> {:error, "#{path}: invalid JSON (#{inspect(reason)})"}
    end
  end

  defp vulnerabilities(path, %{"vulnerabilities" => [], "pass" => false}) do
    {:error, "#{path}: pass is false but the vulnerabilities list is empty; refusing a partial merge"}
  end

  defp vulnerabilities(_path, %{"vulnerabilities" => list}) when is_list(list), do: {:ok, list}
  defp vulnerabilities(path, _map), do: {:error, "#{path}: expected a \"vulnerabilities\" list"}

  defp normalise(path, vulnerabilities) do
    vulnerabilities
    |> Enum.reduce_while({:ok, []}, fn vulnerability, {:ok, acc} ->
      case finding(path, vulnerability) do
        {:ok, finding} -> {:cont, {:ok, [finding | acc]}}
        {:error, message} -> {:halt, {:error, message}}
      end
    end)
    |> case do
      {:ok, findings} -> {:ok, Enum.reverse(findings)}
      error -> error
    end
  end

  defp finding(path, %{"dependency" => dependency, "advisory" => advisory})
       when is_map(dependency) and is_map(advisory) do
    with {:ok, package} <- required_string(path, dependency, "package"),
         {:ok, version} <- required_string(path, dependency, "version"),
         {:ok, id} <- required_string(path, advisory, "id") do
      {:ok,
       Finding.new(
         id: id,
         check: :mix_audit,
         kind: :security,
         severity: Finding.severity_from_string(advisory["severity"]),
         package: package,
         version: version,
         path: dependency["lockfile"] || "mix.lock",
         message: "#{package} #{version} is affected by #{id}: #{advisory["title"] || "security advisory"}",
         remediation: remediation(advisory),
         sources: ["mix_audit"]
       )}
    end
  end

  defp finding(path, _vulnerability) do
    {:error, "#{path}: each vulnerability needs a dependency and an advisory object"}
  end

  defp required_string(path, map, key) do
    case Map.get(map, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _other -> {:error, "#{path}: vulnerability is missing #{key}"}
    end
  end

  defp remediation(advisory) do
    case List.wrap(advisory["first_patched_versions"]) do
      [] -> "upgrade to a patched version"
      [version | _] -> "upgrade to #{version} or later"
    end
  end
end
