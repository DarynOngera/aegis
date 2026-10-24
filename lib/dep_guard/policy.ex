defmodule DepGuard.Policy do
  @moduledoc """
  The team's dependency-security policy, loaded from `.dep_guard.exs`.

  The file holds a single plain-data map (no code). A missing file means the
  strictest policy: no waivers, Hex only, outer checksums required.

  Every waiver (an ignored advisory, an ignored retirement, an allowed
  downgrade) needs a `:reason` and an `:expires` date (ISO 8601), and the date
  may not be further away than `:max_ignore_days`. Expired waivers stop being
  applied and fail the policy check, so exceptions cannot quietly become permanent.
  """

  defstruct ignore_advisories: [],
            ignore_retirements: [],
            allow_downgrades: [],
            allowed_git: [],
            allowed_repos: ["hexpm"],
            max_ignore_days: 90,
            require_outer_checksum: true

  @type t :: %__MODULE__{}

  @known_keys ~w(ignore_advisories ignore_retirements allow_downgrades allowed_git
                 allowed_repos max_ignore_days require_outer_checksum)a

  @spec load(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def load(path) do
    case File.read(path) do
      {:ok, source} ->
        case DepGuard.Literal.parse(source) do
          {:ok, term} -> from_term(term, path)
          {:error, message} -> {:error, "#{path} #{message}"}
        end

      {:error, :enoent} ->
        {:ok, %__MODULE__{}}

      {:error, reason} ->
        {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  defp from_term(map, path) when is_map(map) do
    case Map.keys(map) -- @known_keys do
      [] -> {:ok, struct(__MODULE__, map)}
      unknown -> {:error, "#{path}: unknown keys #{inspect(unknown)} (known: #{inspect(@known_keys)})"}
    end
  end

  defp from_term(_other, path), do: {:error, "#{path} must contain a single map"}

  # -- What is applied to the audit tools ------------------------------------

  @doc "Advisory IDs (including aliases) of waivers that have not expired."
  def advisory_ids(%__MODULE__{} = p, today) do
    p.ignore_advisories
    |> Enum.filter(&unexpired?(&1, today))
    |> Enum.flat_map(&ids/1)
    |> Enum.uniq()
  end

  @doc """
  Environment for `mix hex.audit`. Always sets both variables (to `nil`, which
  unsets them, when there is nothing to ignore) so an ignore list injected through
  the CI environment cannot bypass the policy.
  """
  def hex_env(%__MODULE__{} = p, today) do
    retirements =
      p.ignore_retirements
      |> Enum.filter(&unexpired?(&1, today))
      |> Enum.flat_map(fn
        %{package: pkg} = w when is_binary(pkg) ->
          case Map.get(w, :version) do
            nil -> [pkg]
            version -> ["#{pkg}@#{version}"]
          end

        _ ->
          []
      end)

    [
      {"HEX_IGNORE_ADVISORIES", join_or_nil(advisory_ids(p, today))},
      {"HEX_IGNORE_RETIREMENTS", join_or_nil(retirements)}
    ]
  end

  @doc "Downgrade packages allowed by unexpired waivers."
  def allowed_downgrades(%__MODULE__{} = p, today) do
    for %{package: pkg} = w <- p.allow_downgrades, is_binary(pkg), unexpired?(w, today), do: pkg
  end

  # -- Policy hygiene ----------------------------------------------------------

  @doc """
  Problems with the policy itself. `packages` is a map of Hex package name =>
  locked version (see `DepGuard.Lock.hex_versions/1`).
  """
  @spec problems(t(), %{optional(String.t()) => String.t()}, Date.t()) :: [String.t()]
  def problems(%__MODULE__{} = p, packages, today) do
    waivers("ignore_advisories", p.ignore_advisories, [:id, :package, :reason, :expires], p, packages, today) ++
      waivers("ignore_retirements", p.ignore_retirements, [:package, :reason, :expires], p, packages, today) ++
      waivers("allow_downgrades", p.allow_downgrades, [:package, :reason, :expires], p, packages, today) ++
      git_problems(p.allowed_git) ++
      repo_problems(p.allowed_repos)
  end

  defp waivers(label, list, required, p, packages, today) when is_list(list) do
    Enum.flat_map(list, fn
      %{} = w -> waiver(label, w, required, p, packages, today)
      other -> ["#{label}: each entry must be a map, got #{inspect(other)}"]
    end)
  end

  defp waivers(label, other, _required, _p, _packages, _today),
    do: ["#{label} must be a list, got #{inspect(other)}"]

  defp waiver(label, w, required, p, packages, today) do
    name = "#{label} #{inspect(w[:id] || w[:package])}"

    case Enum.filter(required, &blank?(Map.get(w, &1))) do
      [] ->
        expiry_problems(name, w.expires, p.max_ignore_days, today) ++
          stale_problems(name, w, packages)

      missing ->
        ["#{name}: missing #{Enum.map_join(missing, ", ", &inspect/1)}"]
    end
  end

  defp expiry_problems(name, expires, max_days, today) do
    case is_binary(expires) && Date.from_iso8601(expires) do
      {:ok, date} ->
        cond do
          Date.compare(date, today) == :lt ->
            ["#{name}: expired on #{date}. Fix the dependency, or renew the waiver after a fresh review."]

          Date.diff(date, today) > max_days ->
            ["#{name}: expires #{date}, more than #{max_days} days away (max_ignore_days)."]

          true ->
            []
        end

      _ ->
        ["#{name}: expires #{inspect(expires)} is not an ISO 8601 date (YYYY-MM-DD)"]
    end
  end

  defp stale_problems(name, %{package: pkg} = w, packages) do
    case Map.fetch(packages, pkg) do
      :error ->
        ["#{name}: #{pkg} is no longer in mix.lock. Delete this entry."]

      {:ok, locked} ->
        case Map.get(w, :version) do
          nil -> []
          ^locked -> []
          other -> ["#{name}: pinned to #{other} but mix.lock has #{locked}. Delete or update this entry."]
        end
    end
  end

  defp git_problems(list) when is_list(list) do
    for entry <- list, not (is_map(entry) and is_binary(entry[:app]) and is_binary(entry[:url])) do
      "allowed_git entries must look like %{app: \"name\", url: \"...\"}, got #{inspect(entry)}"
    end
  end

  defp git_problems(other), do: ["allowed_git must be a list, got #{inspect(other)}"]

  defp repo_problems(list) when is_list(list) do
    for repo <- list, not is_binary(repo), do: "allowed_repos entries must be strings, got #{inspect(repo)}"
  end

  defp repo_problems(other), do: ["allowed_repos must be a list, got #{inspect(other)}"]

  # -- helpers -----------------------------------------------------------------

  defp ids(w) do
    [Map.get(w, :id) | List.wrap(Map.get(w, :aliases))] |> Enum.filter(&is_binary/1)
  end

  defp unexpired?(%{expires: expires}, today) when is_binary(expires) do
    case Date.from_iso8601(expires) do
      {:ok, date} -> Date.compare(date, today) != :lt
      _ -> false
    end
  end

  defp unexpired?(_other, _today), do: false

  defp join_or_nil([]), do: nil
  defp join_or_nil(list), do: Enum.join(list, ",")

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false
end
