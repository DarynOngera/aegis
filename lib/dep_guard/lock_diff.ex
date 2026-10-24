defmodule DepGuard.LockDiff do
  @moduledoc """
  Compares two lockfiles and flags changes that deserve a human look.

  Errors (fail the suite):
    * same version, different checksum (the artifact behind a locked version changed)
    * downgrade (unless waived in the policy)
    * package moved to a different source (Hex <-> git) or a different Hex repo
    * git dependency moved to a different URL

  Notices (printed, do not fail): new packages, removed packages, git ref changes.
  """

  alias DepGuard.Lock.Entry

  @type finding :: %{severity: :error | :notice, message: String.t()}

  @doc "Reads `path` as it exists at git `ref`, relative to `root`."
  @spec read_at_ref(Path.t(), String.t(), String.t()) ::
          {:ok, String.t()} | :missing | {:error, String.t()}
  def read_at_ref(root, ref, path \\ "mix.lock") do
    case System.cmd("git", ["show", "#{ref}:./#{path}"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        {:ok, out}

      {out, _status} ->
        if Regex.match?(~r/(does not exist in|exists on disk, but not in)/, out) do
          :missing
        else
          {:error,
           String.trim(out) <>
             " (in CI, check out with full history, e.g. actions/checkout `fetch-depth: 0`)"}
        end
    end
  end

  @spec diff(map(), map()) :: %{added: [Entry.t()], removed: [Entry.t()], changed: [{Entry.t(), Entry.t()}]}
  def diff(old, new) do
    added = for {app, e} <- Enum.sort(new), not Map.has_key?(old, app), do: e
    removed = for {app, e} <- Enum.sort(old), not Map.has_key?(new, app), do: e

    changed =
      new
      |> Enum.sort()
      |> Enum.flat_map(fn {app, n} ->
        case Map.fetch(old, app) do
          {:ok, o} when o != n -> [{o, n}]
          _ -> []
        end
      end)

    %{added: added, removed: removed, changed: changed}
  end

  @spec findings(map(), [String.t()]) :: [finding()]
  def findings(%{added: added, removed: removed, changed: changed}, allowed_downgrades \\ []) do
    Enum.map(added, &notice("new dependency #{label(&1)}")) ++
      Enum.map(removed, &notice("removed dependency #{label(&1)}")) ++
      Enum.flat_map(changed, fn {o, n} -> classify(o, n, allowed_downgrades) end)
  end

  defp classify(%Entry{source: s1} = o, %Entry{source: s2} = n, _allowed) when s1 != s2 do
    [error("#{n.app}: source changed from #{s1} to #{s2} (#{label(o)} -> #{label(n)})")]
  end

  defp classify(%Entry{source: :hex} = o, %Entry{source: :hex} = n, allowed) do
    repo =
      if o.repo != n.repo,
        do: [error("#{n.app}: Hex repo changed from #{inspect(o.repo)} to #{inspect(n.repo)}")],
        else: []

    repo ++ classify_hex_version(o, n, allowed)
  end

  defp classify(%Entry{source: :git} = o, %Entry{source: :git} = n, _allowed) do
    cond do
      o.url != n.url -> [error("#{n.app}: git URL changed from #{o.url} to #{n.url}")]
      o.ref != n.ref -> [notice("#{n.app}: git ref changed #{short(o.ref)} -> #{short(n.ref)}")]
      true -> []
    end
  end

  defp classify(_o, _n, _allowed), do: []

  defp classify_hex_version(o, n, allowed) do
    cond do
      o.version == n.version and checksum_changed?(o, n) ->
        [
          error(
            "#{n.app} #{n.version}: checksum changed but the version did not. " <>
              "The artifact behind a locked version differs from before. Treat it as possibly " <>
              "tampered with and verify on hex.pm before accepting (a package can legitimately be " <>
              "replaced shortly after publishing, but that is rare)."
          )
        ]

      o.version == n.version ->
        []

      compare(o.version, n.version) == :gt ->
        if n.package in allowed do
          [notice("#{n.app}: downgrade #{o.version} -> #{n.version} (waived in policy)")]
        else
          [
            error(
              "#{n.app}: downgraded #{o.version} -> #{n.version}. Downgrades are a common way to " <>
                "reintroduce a vulnerable version; add an allow_downgrades waiver if intentional."
            )
          ]
        end

      true ->
        []
    end
  end

  # Only compare checksums that exist on both sides; an older lock without an
  # outer checksum gaining one is not tampering.
  defp checksum_changed?(o, n) do
    differs?(o.checksum, n.checksum) or differs?(o.outer_checksum, n.outer_checksum)
  end

  defp differs?(a, b) when is_binary(a) and is_binary(b), do: a != b
  defp differs?(_a, _b), do: false

  defp compare(a, b) do
    with {:ok, va} <- Version.parse(a), {:ok, vb} <- Version.parse(b) do
      Version.compare(va, vb)
    else
      _ -> :unknown
    end
  end

  defp label(%Entry{source: :hex} = e), do: "#{e.app} #{e.version}"
  defp label(%Entry{source: :git} = e), do: "#{e.app} (git #{short(e.ref)})"
  defp label(%Entry{} = e), do: "#{e.app} (#{e.source})"

  defp short(ref) when is_binary(ref), do: String.slice(ref, 0, 8)
  defp short(other), do: inspect(other)

  defp error(message), do: %{severity: :error, message: message}
  defp notice(message), do: %{severity: :notice, message: message}
end
