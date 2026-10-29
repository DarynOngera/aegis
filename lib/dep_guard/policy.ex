defmodule DepGuard.Policy do
  @moduledoc """
  Dependency-security policy, in two layers.

  The org policy is a complete policy file, pinned by commit SHA in CI and
  verified by SHA-256 when passed to the scanner. A project's `.dep_guard.exs`
  may only contain waivers; it cannot change allowlists, thresholds or source
  requirements. A missing project file means no waivers.

  Waivers need a `:reason` and an `:expires` date (ISO 8601) no further away
  than `:max_ignore_days`. Expired waivers stop being applied and fail the
  policy check, so exceptions cannot quietly become permanent.
  """

  alias DepGuard.Finding

  defstruct schema_version: 1,
            ignore_advisories: [],
            ignore_retirements: [],
            allow_downgrades: [],
            allow_git_refs: [],
            allowed_git: [],
            allowed_repos: ["hexpm"],
            max_ignore_days: 90,
            require_outer_checksum: true

  @type t :: %__MODULE__{}

  @policy_keys ~w(schema_version ignore_advisories ignore_retirements allow_downgrades
                  allow_git_refs allowed_git allowed_repos max_ignore_days
                  require_outer_checksum)a
  @waiver_keys ~w(ignore_advisories ignore_retirements allow_downgrades allow_git_refs)a

  @doc "Loads a complete policy file (the org layer)."
  @spec load(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def load(path) do
    case read_term(path, allow_missing: true) do
      {:ok, nil} -> {:ok, %__MODULE__{}}
      {:ok, term} -> validate(term, path)
      {:error, message} -> {:error, message}
    end
  end

  @doc """
  Loads the org policy and the project overlay, then merges them.

  `opts`:
    * `:org` - org policy path, or nil for the strict default
    * `:org_sha256` - expected SHA-256 of the org file
    * `:project` - project policy path (waivers only)

  Returns the merged policy and the hashes to record in the report.
  """
  @spec load_layered(keyword()) ::
          {:ok, %{policy: t(), hashes: map()}} | {:error, String.t()}
  def load_layered(opts) do
    org_path = Keyword.get(opts, :org)
    project_path = Keyword.get(opts, :project)

    with {:ok, org, org_sha} <- load_org(org_path, Keyword.get(opts, :org_sha256)),
         {:ok, overlay, project_sha} <- load_project(project_path) do
      {:ok, %{policy: merge(org, overlay), hashes: hashes(org_path, org_sha, project_path, project_sha)}}
    end
  end

  defp load_org(nil, expected) do
    if expected not in [nil, ""] do
      {:error, "--org-policy-sha256 was given without --org-policy"}
    else
      {:ok, %__MODULE__{}, nil}
    end
  end

  defp load_org(path, expected) do
    with {:ok, term} <- read_term(path, allow_missing: false),
         {:ok, sha} <- verify_sha(path, expected),
         {:ok, policy} <- validate(term, path) do
      {:ok, policy, sha}
    end
  end

  defp load_project(nil), do: {:ok, %{}, nil}

  defp load_project(path) do
    case read_term(path, allow_missing: true) do
      {:ok, nil} -> {:ok, %{}, nil}
      {:ok, term} -> validate_project(term, path)
      {:error, message} -> {:error, message}
    end
  end

  defp hashes(org_path, org_sha, project_path, project_sha) do
    %{
      org_sha256: org_sha,
      project_sha256: project_sha,
      org_path: org_path,
      project_path: project_path
    }
  end

  @doc "Reads a policy literal from disk without evaluating code."
  @spec read_term(Path.t(), keyword()) :: {:ok, term() | nil} | {:error, String.t()}
  def read_term(path, opts \\ []) do
    case File.read(path) do
      {:ok, source} ->
        case DepGuard.Literal.parse(source) do
          {:ok, term} -> {:ok, term}
          {:error, message} -> {:error, "#{path} #{message}"}
        end

      {:error, :enoent} ->
        if Keyword.get(opts, :allow_missing, false) do
          {:ok, nil}
        else
          {:error, "#{path} not found"}
        end

      {:error, reason} ->
        {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  @spec verify_sha(Path.t(), String.t() | nil) :: {:ok, String.t()} | {:error, String.t()}
  def verify_sha(path, expected) do
    {:ok, source} = File.read(path)
    actual = :crypto.hash(:sha256, source) |> Base.encode16(case: :lower)

    case expected do
      value when value in [nil, ""] ->
        {:ok, actual}

      ^actual ->
        {:ok, actual}

      _other ->
        {:error, "#{path} SHA-256 is #{actual}, but the pinned value is #{expected}. Policy may have changed."}
    end
  end

  @doc "Validates a complete policy map and returns the struct."
  @spec validate(term(), Path.t()) :: {:ok, t()} | {:error, String.t()}
  def validate(term, path \\ "policy")

  def validate(term, path) when is_map(term) do
    with :ok <- only_known(term, @policy_keys, path),
         :ok <- schema_version(term, path),
         :ok <- field_types(term, path) do
      {:ok, struct(__MODULE__, Map.take(term, @policy_keys))}
    end
  end

  def validate(_term, path), do: {:error, "#{path} must contain a single map"}

  @doc "Validates a project overlay: waivers only."
  @spec validate_project(term(), Path.t()) :: {:ok, map(), String.t()} | {:error, String.t()}
  def validate_project(term, path) when is_map(term) do
    with :ok <- only_known(term, @waiver_keys, path),
         :ok <- waiver_lists(term, path) do
      {:ok, Map.take(term, @waiver_keys), sha256_file(path)}
    end
  end

  def validate_project(_term, path), do: {:error, "#{path} must contain a single map of waivers"}

  defp only_known(term, known, path) do
    case Map.keys(term) -- known do
      [] -> :ok
      unknown -> {:error, "#{path}: unknown keys #{inspect(unknown)} (known: #{inspect(known)})"}
    end
  end

  defp schema_version(%{schema_version: 1}, _path), do: :ok

  defp schema_version(%{schema_version: other}, path),
    do: {:error, "#{path}: schema_version must be 1, got #{inspect(other)}"}

  defp schema_version(_term, _path), do: :ok

  defp field_types(term, path) do
    Enum.find_value(
      [
        {:ignore_advisories, &iso_list?/1},
        {:ignore_retirements, &iso_list?/1},
        {:allow_downgrades, &iso_list?/1},
        {:allow_git_refs, &iso_list?/1},
        {:allowed_git, &iso_list?/1},
        {:allowed_repos, &string_list?/1},
        {:max_ignore_days, &(is_integer(&1) and &1 > 0)},
        {:require_outer_checksum, &is_boolean/1}
      ],
      :ok,
      fn {key, valid?} ->
        case Map.fetch(term, key) do
          {:ok, nil} ->
            {:error, "#{path}: #{key} must not be nil"}

          {:ok, value} ->
            if valid?.(value), do: nil, else: {:error, "#{path}: #{key} has the wrong type (#{inspect(value)})"}

          :error ->
            nil
        end
      end
    )
  end

  defp iso_list?(value), do: is_list(value)
  defp string_list?(value), do: is_list(value) and Enum.all?(value, &is_binary/1)

  defp waiver_lists(term, path) do
    Enum.find_value(@waiver_keys, :ok, fn key ->
      case Map.fetch(term, key) do
        {:ok, value} when is_list(value) -> nil
        {:ok, value} -> {:error, "#{path}: #{key} must be a list, got #{inspect(value)}"}
        :error -> nil
      end
    end)
  end

  @doc "Adds project waivers to the org policy."
  @spec merge(t(), map()) :: t()
  def merge(%__MODULE__{} = org, overlay) when is_map(overlay) do
    %{
      org
      | ignore_advisories: org.ignore_advisories ++ Map.get(overlay, :ignore_advisories, []),
        ignore_retirements: org.ignore_retirements ++ Map.get(overlay, :ignore_retirements, []),
        allow_downgrades: org.allow_downgrades ++ Map.get(overlay, :allow_downgrades, []),
        allow_git_refs: org.allow_git_refs ++ Map.get(overlay, :allow_git_refs, [])
    }
  end

  # -- waivers ----------------------------------------------------------------

  @doc "Applies an unexpired waiver to a finding, if one matches."
  @spec waive(t(), Finding.t(), Date.t()) :: Finding.t()
  def waive(%__MODULE__{} = policy, %Finding{} = finding, today) do
    case matching_waiver(policy, finding, today) do
      nil -> finding
      waiver -> %{finding | waived: waiver}
    end
  end

  defp matching_waiver(policy, %Finding{} = finding, today) do
    advisory_waiver(policy, finding, today) ||
      retirement_waiver(policy, finding, today) ||
      lock_waiver(policy, finding, today)
  end

  defp advisory_waiver(policy, %Finding{} = finding, today) do
    ids = [finding.id | finding.aliases] |> Enum.filter(&is_binary/1)

    Enum.find(active(policy.ignore_advisories, today), fn waiver ->
      Enum.any?(waiver_ids(waiver), &(&1 in ids)) and package_matches?(waiver, finding)
    end)
  end

  defp retirement_waiver(policy, %Finding{check: :retirements} = finding, today) do
    Enum.find(active(policy.ignore_retirements, today), fn waiver ->
      Map.get(waiver, :package) == finding.package and version_matches?(waiver, finding)
    end)
  end

  defp retirement_waiver(_policy, _finding, _today), do: nil

  defp lock_waiver(policy, %Finding{check: :lock_changes} = finding, today) do
    case finding.rule do
      :downgrade -> Enum.find(active(policy.allow_downgrades, today), &specific_package_matches?(&1, finding))
      :git_ref -> Enum.find(active(policy.allow_git_refs, today), &app_matches?(&1, finding))
      _ -> nil
    end
  end

  defp lock_waiver(_policy, _finding, _today), do: nil

  # Lock waivers must name the thing they waive. A missing key is not a
  # wildcard here; it would silently waive every package or app.
  defp specific_package_matches?(waiver, finding) do
    case Map.get(waiver, :package) do
      package when is_binary(package) and package != "" -> package == finding.package
      _other -> false
    end
  end

  defp app_matches?(waiver, finding) do
    case Map.get(waiver, :app) do
      app when is_binary(app) and app != "" -> app == finding.package
      _other -> false
    end
  end

  # An advisory waiver must name its package. A missing key is never a wildcard, or one waiver
  # would cover the same advisory ID on every package.
  defp package_matches?(waiver, finding), do: specific_package_matches?(waiver, finding)

  defp version_matches?(waiver, finding) do
    case Map.get(waiver, :version) do
      nil -> true
      version -> version == finding.version
    end
  end

  defp waiver_ids(waiver),
    do: [Map.get(waiver, :id) | List.wrap(Map.get(waiver, :aliases))] |> Enum.filter(&is_binary/1)

  defp active(waivers, today) when is_list(waivers) do
    Enum.filter(waivers, &(is_map(&1) and unexpired?(&1, today)))
  end

  defp active(_other, _today), do: []

  @doc "Active downgrade waivers."
  def allowed_downgrades(%__MODULE__{} = p, today), do: active(p.allow_downgrades, today)

  @doc "Active git-ref waivers."
  def allowed_git_refs(%__MODULE__{} = p, today), do: active(p.allow_git_refs, today)

  # -- Policy hygiene ---------------------------------------------------------

  @doc """
  Problems with the policy itself. `packages` is a map of Hex package name =>
  locked version (see `DepGuard.Lock.hex_versions/1`).
  """
  @spec problems(t(), %{optional(String.t()) => String.t()}, Date.t()) :: [String.t()]
  def problems(%__MODULE__{} = p, packages, today) do
    waivers("ignore_advisories", p.ignore_advisories, [:id, :package, :reason, :expires], p, packages, today) ++
      waivers("ignore_retirements", p.ignore_retirements, [:package, :reason, :expires], p, packages, today) ++
      waivers("allow_downgrades", p.allow_downgrades, [:package, :reason, :expires], p, packages, today) ++
      waivers("allow_git_refs", p.allow_git_refs, [:app, :reason, :expires], p, packages, today) ++
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
    name = "#{label} #{inspect(w[:id] || w[:package] || w[:app])}"

    case Enum.filter(required, &blank?(Map.get(w, &1))) do
      [] ->
        expiry_problems(name, w[:expires], p.max_ignore_days, today) ++
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

  defp stale_problems(name, %{package: pkg} = w, packages) when is_binary(pkg) do
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

  defp stale_problems(_name, _waiver, _packages), do: []

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

  # -- helpers ----------------------------------------------------------------

  defp unexpired?(%{expires: expires}, today) when is_binary(expires) do
    case Date.from_iso8601(expires) do
      {:ok, date} -> Date.compare(date, today) != :lt
      _ -> false
    end
  end

  defp unexpired?(_other, _today), do: false

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false

  defp sha256_file(path) do
    path |> File.read!() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
  end
end
