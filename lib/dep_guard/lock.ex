defmodule DepGuard.Lock do
  @moduledoc """
  Reads `mix.lock` as plain data (see `DepGuard.Literal`) and normalises entries.

  Nothing here calls Mix: the lockfile is input, not part of a build.
  """

  alias DepGuard.Finding

  defmodule Entry do
    @moduledoc false
    @enforce_keys [:app, :source]
    defstruct [
      :app,
      :package,
      :source,
      :version,
      :checksum,
      :outer_checksum,
      :repo,
      :url,
      :ref,
      :raw_sha256
    ]

    @type t :: %__MODULE__{}
  end

  @type entry :: Entry.t()
  @type t :: %{optional(String.t()) => entry()}
  @type package :: %{version: String.t(), repo: String.t() | nil, app: String.t()}

  @spec read(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def read(path) do
    case File.read(path) do
      {:ok, contents} ->
        case parse_entries(contents) do
          {:ok, entries} -> {:ok, entries}
          {:error, message} -> {:error, "#{path}: #{message}"}
        end

      {:error, :enoent} ->
        {:error, "#{path} not found. Commit mix.lock so dependency versions are pinned."}

      {:error, reason} ->
        {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  @spec parse_entries(String.t()) :: {:ok, t()} | {:error, String.t()}
  def parse_entries(contents) do
    case DepGuard.Literal.parse(contents) do
      {:ok, map} when is_map(map) ->
        Enum.reduce_while(map, {:ok, %{}}, fn {key, raw}, {:ok, acc} ->
          with {:ok, app} <- lock_key(key),
               {:ok, parsed} <- build(app, raw) do
            {:cont, {:ok, Map.put(acc, app, %{parsed | raw_sha256: hash(raw)})}}
          else
            {:error, message} -> {:halt, {:error, message}}
          end
        end)

      {:ok, _other} ->
        {:error, "must contain a single map"}

      {:error, message} ->
        {:error, message}
    end
  end

  defp lock_key(app) when is_binary(app) and app != "", do: {:ok, app}
  defp lock_key(app) when is_atom(app) and not is_nil(app), do: {:ok, Atom.to_string(app)}
  defp lock_key(other), do: {:error, "lock key #{inspect(other)} is not a package name"}

  @doc "Lock entries sorted by app name."
  def sorted(lock), do: lock |> Map.values() |> Enum.sort_by(& &1.app)

  @doc "Map of Hex package name => locked version."
  def hex_versions(lock) do
    for %Entry{source: :hex} = e <- Map.values(lock), into: %{}, do: {e.package, e.version}
  end

  @doc "Map of Hex package name => version, repo and app, for source checks."
  @spec hex_packages(t()) :: %{optional(String.t()) => package()}
  def hex_packages(lock) do
    for %Entry{source: :hex} = e <- Map.values(lock), into: %{} do
      {e.package, %{version: e.version, repo: e.repo, app: e.app}}
    end
  end

  @doc """
  Integrity findings: missing or malformed checksums, git deps not pinned to a
  full commit SHA, entries in a format we do not recognise.
  """
  @spec integrity_findings(t(), boolean()) :: [Finding.t()]
  def integrity_findings(lock, require_outer_checksum \\ true) do
    Enum.flat_map(sorted(lock), fn
      %Entry{source: :hex} = e ->
        checksum_problems(e) ++
          if require_outer_checksum and blank?(e.outer_checksum) do
            [finding(e, :medium, "#{e.app} #{e.version}: lock entry has no outer checksum")]
          else
            []
          end

      %Entry{source: :git} = e ->
        if is_binary(e.ref) and Regex.match?(~r/\A[0-9a-f]{40}\z/, e.ref) do
          []
        else
          [finding(e, :high, "#{e.app}: git dependency is not pinned to a full commit SHA in mix.lock")]
        end

      %Entry{app: app} ->
        [
          Finding.new(
            check: :lockfile,
            kind: :integrity,
            severity: :high,
            package: app,
            path: "mix.lock",
            message: "#{app}: unrecognised mix.lock entry format"
          )
        ]
    end)
  end

  defp checksum_problems(%Entry{} = e) do
    missing =
      if blank?(e.checksum) do
        [finding(e, :high, "#{e.app} #{e.version}: lock entry has no checksum")]
      else
        []
      end

    malformed =
      if blank?(e.checksum) or valid_checksum?(e.checksum) do
        []
      else
        [finding(e, :high, "#{e.app} #{e.version}: checksum is not a 64-character hex digest")]
      end

    missing ++ malformed
  end

  defp valid_checksum?(value), do: Regex.match?(~r/\A[0-9a-f]{64}\z/, value)

  defp finding(%Entry{} = e, severity, message) do
    Finding.new(
      check: :lockfile,
      kind: :integrity,
      severity: severity,
      package: e.app,
      version: e.version,
      path: "mix.lock",
      message: message,
      remediation: "run `mix deps.get` to rewrite the lock entry, or fix the lockfile by hand"
    )
  end

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false

  defp build(app, {:hex, pkg, version, checksum, _tools, _deps, repo, outer}) do
    with {:ok, package} <- package_name(pkg, app),
         {:ok, version} <- text(version, "version", app),
         :ok <- optional_text(checksum, "checksum", app),
         :ok <- optional_text(repo, "repo", app),
         :ok <- optional_text(outer, "outer checksum", app) do
      {:ok,
       %Entry{
         app: app,
         package: package,
         source: :hex,
         version: version,
         checksum: checksum,
         outer_checksum: outer,
         repo: repo
       }}
    end
  end

  defp build(app, {:hex, pkg, version, checksum, _tools, _deps, repo}) do
    with {:ok, package} <- package_name(pkg, app),
         {:ok, version} <- text(version, "version", app),
         :ok <- optional_text(checksum, "checksum", app),
         :ok <- optional_text(repo, "repo", app) do
      {:ok,
       %Entry{
         app: app,
         package: package,
         source: :hex,
         version: version,
         checksum: checksum,
         repo: repo
       }}
    end
  end

  defp build(app, {:hex, pkg, version, checksum, _tools, _deps}) do
    with {:ok, package} <- package_name(pkg, app),
         {:ok, version} <- text(version, "version", app),
         :ok <- optional_text(checksum, "checksum", app) do
      {:ok,
       %Entry{
         app: app,
         package: package,
         source: :hex,
         version: version,
         checksum: checksum,
         repo: "hexpm"
       }}
    end
  end

  defp build(app, {:git, url, ref, _opts}) do
    with {:ok, url} <- text(url, "git URL", app),
         {:ok, ref} <- text(ref, "git ref", app) do
      {:ok, %Entry{app: app, source: :git, url: url, ref: ref}}
    end
  end

  defp build(app, _other), do: {:ok, %Entry{app: app, source: :unknown}}

  defp package_name(value, _app) when is_binary(value) and value != "", do: {:ok, value}
  defp package_name(value, _app) when is_atom(value) and not is_nil(value), do: {:ok, Atom.to_string(value)}
  defp package_name(value, app), do: {:error, "#{app}: package is not a name (#{inspect(value)})"}

  defp text(value, _field, _app) when is_binary(value) and value != "", do: {:ok, value}
  defp text(value, field, app), do: {:error, "#{app}: #{field} is not a string (#{inspect(value)})"}

  defp optional_text(nil, _field, _app), do: :ok
  defp optional_text(value, _field, _app) when is_binary(value), do: :ok
  defp optional_text(value, field, app), do: {:error, "#{app}: #{field} is not a string (#{inspect(value)})"}

  # Includes tools/deps: a change there is still a change to the locked artifact.
  defp hash(term), do: :crypto.hash(:sha256, :erlang.term_to_binary(term)) |> Base.encode16(case: :lower)
end
