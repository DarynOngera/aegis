defmodule DepGuard.Checks do
  @moduledoc """
  The individual checks. Each returns a list of problem strings; empty means pass.
  """

  alias DepGuard.{EefFeed, Lock, LockDiff, Policy, Runner}

  @type ctx :: %{
          root: Path.t(),
          lock: Lock.t(),
          policy: Policy.t(),
          today: Date.t(),
          mix_env: atom()
        }

  @spec context(keyword()) :: {:ok, ctx()} | {:error, String.t()}
  def context(opts) do
    root = opts |> Keyword.get(:root, File.cwd!()) |> Path.expand()
    policy_path = Path.join(root, Keyword.get(opts, :policy, ".dep_guard.exs"))

    with {:ok, policy} <- Policy.load(policy_path),
         {:ok, lock} <- Lock.read(Path.join(root, "mix.lock")) do
      {:ok,
       %{
         root: root,
         lock: lock,
         policy: policy,
         today: Keyword.get(opts, :today, Date.utc_today()),
         mix_env: Keyword.get(opts, :mix_env, Mix.env())
       }}
    end
  end

  # -- offline checks ----------------------------------------------------------

  @doc "mix.lock is plain data, every package has checksums, git deps are pinned to a commit."
  def lockfile(%{lock: lock, policy: policy}) do
    Lock.integrity_problems(lock, policy.require_outer_checksum)
  end

  @doc "Every dependency comes from an allowed Hex repo, or an allowed git URL."
  def sources(%{lock: lock, policy: policy}) do
    Enum.flat_map(Lock.sorted(lock), fn
      %{source: :hex, app: app, repo: repo} ->
        if repo in policy.allowed_repos,
          do: [],
          else: ["#{app}: comes from Hex repo #{inspect(repo)}, not in allowed_repos #{inspect(policy.allowed_repos)}"]

      %{source: :git, app: app, url: url} ->
        case Enum.find(policy.allowed_git, &(is_map(&1) and &1[:app] == app)) do
          nil -> ["#{app}: git dependency #{url} is not listed in allowed_git"]
          %{url: ^url} -> []
          %{url: other} -> ["#{app}: git URL is #{url} but allowed_git expects #{other}"]
        end

      %{app: app} ->
        ["#{app}: unrecognised mix.lock entry"]
    end)
  end

  @doc "Waivers are complete, unexpired, short-lived and still relevant."
  def policy_hygiene(%{policy: policy, lock: lock, today: today}) do
    Policy.problems(policy, Lock.hex_versions(lock), today)
  end

  @doc """
  mix.exs must not carry its own `hex: [ignore_advisories: ..., ignore_retirements: ...]`;
  that route bypasses waiver expiry.
  """
  def project_ignores do
    hex =
      case Mix.Project.config()[:hex] do
        list when is_list(list) -> list
        _ -> []
      end

    for key <- [:ignore_advisories, :ignore_retirements], Keyword.get(hex, key) not in [nil, []] do
      "mix.exs sets hex: [#{key}: ...]. Move it to .dep_guard.exs so it needs a reason and an expiry."
    end
  end

  @doc "Compares mix.lock with the one at `base_ref` and reports suspicious changes."
  def lock_changes(%{root: root, lock: new, policy: policy, today: today}, base_ref) do
    result =
      case LockDiff.read_at_ref(root, base_ref) do
        {:ok, source} -> Lock.parse_entries(source)
        :missing -> {:ok, %{}}
        {:error, message} -> {:error, message}
      end

    case result do
      {:ok, old} ->
        findings =
          old
          |> LockDiff.diff(new)
          |> LockDiff.findings(Policy.allowed_downgrades(policy, today))

        {errors, notices} = Enum.split_with(findings, &(&1.severity == :error))
        Enum.each(notices, &IO.puts("[dep_guard] #{&1.message}"))
        Enum.map(errors, & &1.message)

      {:error, message} ->
        ["cannot compare mix.lock with #{base_ref}: #{message}"]
    end
  end

  # -- online checks -----------------------------------------------------------

  @doc "`mix hex.audit`: retired packages and (Hex >= 2.5) security advisories."
  def hex_audit(%{root: root, policy: policy, today: today, mix_env: mix_env}) do
    ["hex.audit"]
    |> Runner.mix(root: root, mix_env: mix_env, env: Policy.hex_env(policy, today))
    |> report("mix hex.audit")
  end

  @doc "`mix deps.audit` (mix_audit): advisories from elixir-security-advisories."
  def mix_audit(%{root: root, policy: policy, today: today, mix_env: mix_env}) do
    args =
      case Policy.advisory_ids(policy, today) do
        [] -> ["deps.audit"]
        ids -> ["deps.audit", "--ignore-advisory-ids", Enum.join(ids, ",")]
      end

    args
    |> Runner.mix(root: root, mix_env: mix_env, env: Policy.hex_env(policy, today))
    |> report("mix deps.audit",
      missing:
        "mix deps.audit is not available. Add {:mix_audit, \"~> 2.1\", only: [:dev, :test], runtime: false} to deps."
    )
  end

  @doc "EEF CNA OSV feed cross-check (opt-in)."
  def eef_feed(%{lock: lock, policy: policy, today: today}, opts \\ []) do
    EefFeed.check(Lock.hex_versions(lock), Policy.advisory_ids(policy, today), opts)
  end

  defp report(result, name, opts \\ [])

  defp report({:ok, _output}, _name, _opts), do: []

  defp report({:failed, status, output}, name, _opts) do
    ["#{name} exited with status #{status}:\n#{indent(output)}"]
  end

  defp report({:missing_task, output}, name, opts) do
    [Keyword.get(opts, :missing, "#{name} is not available:\n#{indent(output)}")]
  end

  defp report({:error, message}, name, _opts), do: ["#{name}: #{message}"]

  defp indent(text) do
    text |> String.trim() |> String.split("\n") |> Enum.map_join("\n", &("    " <> &1))
  end
end
