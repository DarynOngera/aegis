defmodule DepGuard.LockDiff do
  @moduledoc """
  Compares two lockfiles and flags changes that deserve a human look.

  Errors (gate):
    * package renamed, moved source or Hex repo
    * checksum removed or changed under the same version
    * downgrade (unless waived)
    * git URL or ref changed (unless waived)

  Notices (reported, do not gate): new/removed packages, a checksum gaining an
  outer value, and a lock entry whose `tools`/`deps` changed without a version
  change.
  """

  alias DepGuard.Finding
  alias DepGuard.Lock.Entry

  @type opts :: %{downgrades: [map()], git_refs: [map()], today: Date.t()}

  @doc "Reads `path` as it exists at git `ref`, relative to `root`."
  @spec read_at_ref(Path.t(), String.t(), String.t()) ::
          {:ok, String.t()} | :missing | {:error, String.t()}
  def read_at_ref(root, ref, path \\ "mix.lock") do
    if System.find_executable("git") do
      git_show(root, ref, path)
    else
      {:error, "git is not available; pass --base-lock instead"}
    end
  end

  defp git_show(root, ref, path) do
    case System.cmd("git", ["show", "#{ref}:./#{path}"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        {:ok, out}

      {out, _status} ->
        if Regex.match?(~r/(does not exist in|exists on disk, but not in)/, out) do
          :missing
        else
          {:error,
           String.trim(out) <>
             " (in CI, check out with full history, or pass --base-lock instead)"}
        end
    end
  end

  @spec diff(map(), map()) :: %{
          added: [Entry.t()],
          removed: [Entry.t()],
          changed: [{Entry.t(), Entry.t()}],
          renamed: [{Entry.t(), Entry.t()}]
        }
  def diff(old, new) do
    raw_added = for {app, e} <- Enum.sort(new), not Map.has_key?(old, app), do: e
    raw_removed = for {app, e} <- Enum.sort(old), not Map.has_key?(new, app), do: e

    renamed =
      for r <- raw_removed, a <- raw_added, r.package == a.package, r.app != a.app, do: {r, a}

    renamed_apps = Enum.map(renamed, fn {r, a} -> {r.app, a.app} end)

    added = Enum.reject(raw_added, fn a -> Enum.any?(renamed_apps, &(elem(&1, 1) == a.app)) end)
    removed = Enum.reject(raw_removed, fn r -> Enum.any?(renamed_apps, &(elem(&1, 0) == r.app)) end)

    changed =
      new
      |> Enum.sort()
      |> Enum.flat_map(fn {app, n} ->
        case Map.fetch(old, app) do
          {:ok, o} when o != n -> [{o, n}]
          _ -> []
        end
      end)

    %{added: added, removed: removed, changed: changed, renamed: renamed}
  end

  @spec findings(map(), opts()) :: [Finding.t()]
  def findings(diff, opts \\ %{downgrades: [], git_refs: [], today: Date.utc_today()}) do
    Enum.map(diff.renamed, fn {o, n} ->
      error(n, :high, "lock key renamed #{o.app} -> #{n.app} (package #{n.package})")
    end) ++
      Enum.map(diff.added, &notice(&1, "new dependency #{label(&1)}")) ++
      Enum.map(diff.removed, &notice(&1, "removed dependency #{label(&1)}")) ++
      Enum.flat_map(diff.changed, fn {old, new} -> classify(old, new, opts) end)
  end

  defp classify(%Entry{source: s1} = o, %Entry{source: s2} = n, _opts) when s1 != s2 do
    [error(n, :high, "#{n.app}: source changed from #{s1} to #{s2} (#{label(o)} -> #{label(n)})")]
  end

  defp classify(%Entry{source: :hex} = o, %Entry{source: :hex} = n, opts) do
    rename_problem(o, n) ++
      repo_problem(o, n) ++
      checksum_problems(o, n) ++
      version_problems(o, n, opts) ++
      raw_problems(o, n)
  end

  defp classify(%Entry{source: :git} = o, %Entry{source: :git} = n, opts) do
    url_problem(o, n) ++ ref_problem(o, n, opts)
  end

  defp classify(_o, _n, _opts), do: []

  defp rename_problem(%Entry{package: p1}, %Entry{package: p2} = n) when p1 != p2 do
    [error(n, :high, "#{n.app}: package changed from #{p1} to #{p2}")]
  end

  defp rename_problem(_o, _n), do: []

  defp repo_problem(%Entry{repo: r1}, %Entry{repo: r2} = n) when r1 != r2 do
    [error(n, :high, "#{n.app}: Hex repo changed from #{inspect(r1)} to #{inspect(r2)}")]
  end

  defp repo_problem(_o, _n), do: []

  defp checksum_problems(%Entry{} = o, %Entry{} = n) do
    cond do
      is_binary(o.checksum) and not is_binary(n.checksum) ->
        [error(n, :high, "#{n.app} #{n.version}: checksum was removed from the lock entry")]

      is_binary(o.outer_checksum) and not is_binary(n.outer_checksum) ->
        [error(n, :high, "#{n.app} #{n.version}: outer checksum was removed from the lock entry")]

      o.version == n.version and is_binary(o.checksum) and is_binary(n.checksum) and o.checksum != n.checksum ->
        [
          error(
            n,
            :high,
            "#{n.app} #{n.version}: checksum changed but the version did not. The artifact behind " <>
              "a locked version differs from before. Verify on hex.pm before accepting."
          )
        ]

      o.version == n.version and is_binary(o.outer_checksum) and is_binary(n.outer_checksum) and
          o.outer_checksum != n.outer_checksum ->
        [
          error(
            n,
            :high,
            "#{n.app} #{n.version}: outer checksum changed but the version did not. Verify on hex.pm."
          )
        ]

      is_nil(o.outer_checksum) and is_binary(n.outer_checksum) ->
        [notice(n, "#{n.app} #{n.version}: outer checksum added")]

      true ->
        []
    end
  end

  defp version_problems(%Entry{version: v}, %Entry{version: v} = _n, _opts), do: []

  defp version_problems(%Entry{} = o, %Entry{} = n, opts) do
    case compare(o.version, n.version) do
      :gt ->
        case waiver(opts.downgrades, n) do
          nil ->
            [
              error(
                n,
                :high,
                "#{n.app}: downgraded #{o.version} -> #{n.version}. Add an allow_downgrades waiver " <>
                  "if this is intentional.",
                :downgrade
              )
            ]

          waiver ->
            [waived(n, waiver, "#{n.app}: downgrade #{o.version} -> #{n.version}", :downgrade)]
        end

      _ ->
        []
    end
  end

  defp raw_problems(%Entry{} = o, %Entry{} = n) do
    cond do
      o.raw_sha256 == n.raw_sha256 -> []
      o.version != n.version -> []
      o.checksum != n.checksum -> []
      o.outer_checksum != n.outer_checksum -> []
      true -> [notice(n, "#{n.app} #{n.version}: lock entry changed without a version change (tools/deps)")]
    end
  end

  defp url_problem(%Entry{url: u1}, %Entry{url: u2} = n) when u1 != u2 do
    [error(n, :high, "#{n.app}: git URL changed from #{u1} to #{u2}")]
  end

  defp url_problem(_o, _n), do: []

  defp ref_problem(%Entry{ref: r1}, %Entry{ref: r1} = _n, _opts), do: []

  defp ref_problem(%Entry{} = o, %Entry{} = n, opts) do
    case waiver(opts.git_refs, n) do
      nil ->
        [
          error(
            n,
            :high,
            "#{n.app}: git ref changed #{short(o.ref)} -> #{short(n.ref)}. Add an allow_git_refs " <>
              "waiver if this is intentional.",
            :git_ref
          )
        ]

      waiver ->
        [waived(n, waiver, "#{n.app}: git ref changed #{short(o.ref)} -> #{short(n.ref)}", :git_ref)]
    end
  end

  defp waiver(waivers, entry) do
    Enum.find(waivers, fn waiver ->
      Map.get(waiver, :app) == entry.app or Map.get(waiver, :package) == entry.package
    end)
  end

  defp compare(a, b) do
    with {:ok, va} <- Version.parse(a), {:ok, vb} <- Version.parse(b) do
      Version.compare(va, vb)
    else
      _ -> :unknown
    end
  end

  defp error(%Entry{} = e, severity, message, rule \\ nil) do
    Finding.new(
      check: :lock_changes,
      kind: :integrity,
      severity: severity,
      package: e.app,
      version: e.version,
      path: "mix.lock",
      rule: rule,
      message: message
    )
  end

  defp notice(%Entry{} = e, message) do
    Finding.new(
      check: :lock_changes,
      kind: :notice,
      severity: :info,
      package: e.app,
      version: e.version,
      path: "mix.lock",
      message: message
    )
  end

  defp waived(%Entry{} = e, waiver, message, rule) do
    Finding.new(
      check: :lock_changes,
      kind: :integrity,
      severity: :high,
      package: e.app,
      version: e.version,
      path: "mix.lock",
      rule: rule,
      message: message,
      waived: waiver
    )
  end

  defp label(%Entry{source: :hex} = e), do: "#{e.app} #{e.version}"
  defp label(%Entry{source: :git} = e), do: "#{e.app} (git #{short(e.ref)})"
  defp label(%Entry{} = e), do: "#{e.app} (#{e.source})"

  defp short(ref) when is_binary(ref), do: String.slice(ref, 0, 8)
  defp short(other), do: inspect(other)
end
