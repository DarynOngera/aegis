defmodule DepGuard.Lock do
  @moduledoc """
  Reads `mix.lock` as plain data (see `DepGuard.Literal`) and normalises entries.
  """

  defmodule Entry do
    @moduledoc false
    @enforce_keys [:app, :source]
    defstruct [:app, :package, :source, :version, :checksum, :outer_checksum, :repo, :url, :ref]

    @type t :: %__MODULE__{}
  end

  @type entry :: Entry.t()
  @type t :: %{optional(String.t()) => entry()}

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
        {:ok,
         Map.new(map, fn {app, raw} ->
           app = to_string(app)
           {app, entry(app, raw)}
         end)}

      {:ok, _other} ->
        {:error, "must contain a single map"}

      {:error, message} ->
        {:error, message}
    end
  end

  @doc "Lock entries sorted by app name."
  def sorted(lock), do: lock |> Map.values() |> Enum.sort_by(& &1.app)

  @doc "Map of Hex package name => locked version."
  def hex_versions(lock) do
    for %Entry{source: :hex} = e <- Map.values(lock), into: %{}, do: {e.package, e.version}
  end

  @doc """
  Integrity problems in the lock: missing checksums, git deps not pinned to a
  full commit SHA, entries in a format we do not recognise.
  """
  @spec integrity_problems(t(), boolean()) :: [String.t()]
  def integrity_problems(lock, require_outer_checksum \\ true) do
    Enum.flat_map(sorted(lock), fn
      %Entry{source: :hex} = e ->
        []
        |> add(blank?(e.checksum), "#{e.app} #{e.version}: lock entry has no checksum")
        |> add(
          require_outer_checksum and blank?(e.outer_checksum),
          "#{e.app} #{e.version}: lock entry has no outer checksum " <>
            "(a current Hex records it on `mix deps.get`; or set require_outer_checksum: false in the policy)"
        )

      %Entry{source: :git} = e ->
        add(
          [],
          not (is_binary(e.ref) and Regex.match?(~r/\A[0-9a-f]{40}\z/, e.ref)),
          "#{e.app}: git dependency is not pinned to a full commit SHA in mix.lock"
        )

      %Entry{app: app} ->
        ["#{app}: unrecognised mix.lock entry format"]
    end)
  end

  defp add(list, true, message), do: list ++ [message]
  defp add(list, false, _message), do: list

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false

  defp entry(app, {:hex, pkg, version, checksum, _tools, _deps, repo, outer}) do
    %Entry{
      app: app,
      package: to_string(pkg),
      source: :hex,
      version: version,
      checksum: checksum,
      outer_checksum: outer,
      repo: repo
    }
  end

  defp entry(app, {:hex, pkg, version, checksum, _tools, _deps, repo}) do
    %Entry{
      app: app,
      package: to_string(pkg),
      source: :hex,
      version: version,
      checksum: checksum,
      repo: repo
    }
  end

  defp entry(app, {:hex, pkg, version, checksum, _tools, _deps}) do
    %Entry{
      app: app,
      package: to_string(pkg),
      source: :hex,
      version: version,
      checksum: checksum,
      repo: "hexpm"
    }
  end

  defp entry(app, {:git, url, ref, _opts}) do
    %Entry{app: app, source: :git, url: url, ref: ref}
  end

  defp entry(app, _other), do: %Entry{app: app, source: :unknown}
end
