defmodule DepGuard.Checks do
  @moduledoc """
  Orchestrates the checks. Every check returns `DepGuard.Finding` structs and
  never prints or exits; the CLI decides what the findings mean.

  No function here calls Mix. The project is read as data: `mix.lock`,
  `mix.exs` (AST only) and the policy files.
  """

  alias DepGuard.{EefFeed, Finding, HexApi, Lock, LockDiff, MixExs, Policy}

  @type ctx :: %{
          root: Path.t(),
          lock: Lock.t(),
          policy: Policy.t(),
          policy_hashes: map(),
          today: Date.t()
        }

  @spec context(keyword()) :: {:ok, ctx()} | {:error, String.t()}
  def context(opts) do
    root = opts |> Keyword.get(:root, File.cwd!()) |> Path.expand()
    project_policy = Keyword.get(opts, :policy) || Path.join(root, ".dep_guard.exs")

    with {:ok, %{policy: policy, hashes: hashes}} <-
           Policy.load_layered(
             org: Keyword.get(opts, :org_policy),
             org_sha256: Keyword.get(opts, :org_policy_sha256),
             project: project_policy
           ),
         {:ok, lock} <- Lock.read(Path.join(root, "mix.lock")) do
      {:ok,
       %{
         root: root,
         lock: lock,
         policy: policy,
         policy_hashes: hashes,
         today: Keyword.get(opts, :today, Date.utc_today())
       }}
    end
  end

  # -- offline checks ----------------------------------------------------------

  @doc "mix.lock is plain data, every package has checksums, git deps are pinned to a commit."
  @spec lockfile(ctx()) :: [Finding.t()]
  def lockfile(%{lock: lock, policy: policy}) do
    Lock.integrity_findings(lock, policy.require_outer_checksum)
  end

  @doc "Every dependency comes from an allowed Hex repo, or an allowed git URL."
  @spec sources(ctx()) :: [Finding.t()]
  def sources(%{lock: lock, policy: policy}) do
    Enum.flat_map(Lock.sorted(lock), fn
      %{source: :hex, app: app, repo: repo, version: version} ->
        if repo in policy.allowed_repos do
          []
        else
          [
            Finding.new(
              check: :sources,
              kind: :policy,
              severity: :high,
              package: app,
              version: version,
              path: "mix.lock",
              message:
                "#{app}: comes from Hex repo #{inspect(repo)}, not in allowed_repos #{inspect(policy.allowed_repos)}"
            )
          ]
        end

      %{source: :git, app: app, url: url} ->
        case Enum.find(policy.allowed_git, &(is_map(&1) and &1[:app] == app)) do
          nil ->
            [
              Finding.new(
                check: :sources,
                kind: :policy,
                severity: :high,
                package: app,
                path: "mix.lock",
                message: "#{app}: git dependency #{url} is not listed in allowed_git"
              )
            ]

          %{url: ^url} ->
            []

          %{url: other} ->
            [
              Finding.new(
                check: :sources,
                kind: :policy,
                severity: :high,
                package: app,
                path: "mix.lock",
                message: "#{app}: git URL is #{url} but allowed_git expects #{other}"
              )
            ]
        end

      %{app: app} ->
        [
          Finding.new(
            check: :sources,
            kind: :policy,
            severity: :high,
            package: app,
            path: "mix.lock",
            message: "#{app}: unrecognised mix.lock entry"
          )
        ]
    end)
  end

  @doc "Waivers are complete, unexpired, short-lived and still relevant."
  @spec policy_hygiene(ctx()) :: [Finding.t()]
  def policy_hygiene(%{policy: policy, lock: lock, today: today}) do
    policy
    |> Policy.problems(Lock.hex_versions(lock), today)
    |> Enum.map(fn message ->
      Finding.new(check: :policy, kind: :policy, severity: :high, path: ".dep_guard.exs", message: message)
    end)
  end

  @doc "mix.exs must not carry its own Hex ignore lists."
  @spec project_ignores(ctx()) :: [Finding.t()]
  def project_ignores(%{root: root}) do
    case MixExs.scan(Path.join(root, "mix.exs")) do
      {:ok, findings} ->
        findings

      {:error, message} ->
        [
          Finding.new(
            check: :mix_exs,
            kind: :operational,
            severity: :high,
            path: "mix.exs",
            message: "cannot inspect mix.exs: #{message}"
          )
        ]
    end
  end

  @doc """
  Compares `mix.lock` with a base lock. `base` is `{:ref, ref}`, `{:file, path}`
  or `nil` (no base comparison).
  """
  @spec lock_changes(ctx(), nil | {:ref, String.t()} | {:file, Path.t()}) :: [Finding.t()]
  def lock_changes(_ctx, nil), do: []

  def lock_changes(%{root: root, lock: new, policy: policy, today: today}, {:ref, ref}) do
    case LockDiff.read_at_ref(root, ref) do
      {:ok, source} -> compare_lock(source, new, policy, today, ref)
      :missing -> compare_lock("%{}", new, policy, today, ref)
      {:error, message} -> [operational("cannot compare mix.lock with #{ref}: #{message}")]
    end
  end

  def lock_changes(%{lock: new, policy: policy, today: today}, {:file, path}) do
    case File.read(path) do
      {:ok, source} -> compare_lock(source, new, policy, today, path)
      {:error, :enoent} -> [operational("base lock #{path} not found")]
      {:error, reason} -> [operational("cannot read base lock #{path}: #{:file.format_error(reason)}")]
    end
  end

  defp compare_lock(source, new, policy, today, label) do
    case Lock.parse_entries(source) do
      {:ok, old} ->
        opts = %{
          downgrades: Policy.allowed_downgrades(policy, today),
          git_refs: Policy.allowed_git_refs(policy, today),
          today: today
        }

        LockDiff.findings(LockDiff.diff(old, new), opts)

      {:error, message} ->
        [operational("cannot parse base lock #{label}: #{message}")]
    end
  end

  # -- online sources ----------------------------------------------------------

  @doc "Native Hex API retirements and security advisories."
  @spec hex_api(ctx(), keyword()) :: map()
  def hex_api(%{lock: lock}, opts \\ []) do
    packages = for {name, info} <- Lock.hex_packages(lock), do: Map.put(info, :name, name)
    HexApi.check(packages, opts)
  end

  @doc "EEF CNA OSV feed cross-check."
  @spec eef_feed(ctx(), keyword()) :: map()
  def eef_feed(%{lock: lock}, opts \\ []) do
    EefFeed.check(Lock.hex_versions(lock), opts)
  end

  defp operational(message) do
    Finding.new(check: :lock_changes, kind: :operational, severity: :high, path: "mix.lock", message: message)
  end
end
