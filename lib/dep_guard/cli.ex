defmodule DepGuard.CLI do
  @moduledoc """
  Command line entry point.

      dep_guard scan --root /workspace [options]
      dep_guard render --input report.json --format sarif --output report.sarif
      dep_guard version

  `scan` runs every enabled check once and builds one report. Renderers project
  that report; `render` re-renders a saved report without touching the network.
  """

  alias DepGuard.{Checks, Finding, MixAudit, Policy, Report}
  alias DepGuard.Report.{Human, JSON, SARIF}

  @version "0.2.0"

  @scan_switches [
    root: :string,
    org_policy: :string,
    org_policy_sha256: :string,
    policy: :string,
    base_ref: :string,
    base_lock: :string,
    mix_audit_report: :string,
    format: :string,
    output: :string,
    fail_on: :string,
    offline: :boolean,
    allow_skipped: :boolean,
    cache_dir: :string,
    today: :string
  ]

  @render_switches [input: :string, format: :string, output: :string]

  @doc "Entry point used by the release. Writes output and halts."
  def main(argv) do
    case run(argv) do
      {:ok, output, code} ->
        if output != "", do: IO.write(output)
        System.halt(code)

      {:error, message} ->
        IO.puts(:stderr, "dep_guard: #{message}")
        System.halt(2)
    end
  end

  @doc "Runs a command and returns `{:ok, output, exit_code}` or `{:error, message}`."
  @spec run([String.t()]) :: {:ok, String.t(), 0 | 1 | 2 | 3} | {:error, String.t()}
  def run(argv) do
    dispatch(argv)
  rescue
    # A crash in a parser or renderer is still an operational failure, not a
    # stack trace and a random exit status.
    exception -> {:error, "unexpected error: #{Exception.message(exception)}"}
  end

  defp dispatch([]), do: help()
  defp dispatch(["scan" | argv]), do: scan(argv)
  defp dispatch(["render" | argv]), do: render(argv)
  defp dispatch(["version"]), do: {:ok, "dep_guard #{@version}\n", 0}
  defp dispatch(["help"]), do: help()
  defp dispatch([other | _]), do: {:error, "unknown command #{inspect(other)}; try `dep_guard help`"}

  defp help do
    {:ok, usage(), 0}
  end

  # -- scan -------------------------------------------------------------------

  defp scan(argv) do
    with {:ok, opts} <- parse(argv, @scan_switches),
         {:ok, format} <- one_of(opts[:format] || "human", ~w(human json sarif), "--format"),
         {:ok, fail_on} <- fail_on(opts[:fail_on] || "high"),
         {:ok, today} <- today(opts[:today]),
         :ok <- exclusive(opts, :base_ref, :base_lock),
         {:ok, base} <- base_input(opts) do
      root = Path.expand(opts[:root] || File.cwd!())

      case Checks.context(
             root: root,
             org_policy: opts[:org_policy],
             org_policy_sha256: opts[:org_policy_sha256],
             policy: opts[:policy],
             today: today
           ) do
        {:ok, ctx} ->
          started = System.monotonic_time(:millisecond)
          report = build_report(ctx, opts, base, started, fail_on)
          render_and_finish(report, format, opts[:output], fail_on)

        {:error, message} ->
          {:error, message}
      end
    end
  end

  defp build_report(ctx, opts, base, started, fail_on) do
    report =
      Report.new(
        project: project_info(ctx.root),
        policy: ctx.policy_hashes,
        inputs: inputs(ctx, base, fail_on, opts),
        version: @version,
        image_digest: System.get_env("DEP_GUARD_IMAGE_DIGEST")
      )

    report =
      report
      |> Report.add_findings(today_notice(opts[:today]))
      |> Report.add_findings(Checks.lockfile(ctx))
      |> Report.add_findings(Checks.sources(ctx))
      |> Report.add_findings(Checks.policy_hygiene(ctx))
      |> Report.add_findings(Checks.project_ignores(ctx))
      |> Report.add_findings(Checks.lock_changes(ctx, base))
      |> run_sources(ctx, opts)
      |> merge_mix_audit(opts[:mix_audit_report])
      |> apply_waivers(ctx)
      |> Report.dedupe()

    Report.finalize(report, duration_ms: System.monotonic_time(:millisecond) - started)
  end

  defp run_sources(report, ctx, opts) do
    fetch_opts = [cache_dir: opts[:cache_dir]]

    # --offline skips the online sources entirely; it never serves them from the
    # cache, so a stale cached advisory cannot pass for a fresh check.
    if opts[:offline] do
      report
      |> Report.put_source(%{name: "hex_api", status: :skipped, reason: "offline"})
      |> Report.put_source(%{name: "eef", status: :skipped, reason: "offline"})
      |> Report.add_findings([
        Finding.new(
          check: :sources,
          kind: :notice,
          severity: :info,
          message:
            "online sources skipped (--offline); the report does not prove advisory coverage" <>
              if(opts[:allow_skipped], do: "", else: ". The scan exits 2 unless --allow-skipped is given")
        )
      ])
    else
      hex = Checks.hex_api(ctx, fetch_opts)
      eef = Checks.eef_feed(ctx, fetch_opts)

      report
      |> Report.put_source(source_entry(hex))
      |> Report.add_findings(hex.findings ++ hex.notices)
      |> Report.put_source(source_entry(eef))
      |> Report.add_findings(eef.findings ++ eef.notices)
    end
  end

  defp source_entry(source) do
    Map.merge(%{name: source.name, status: source.status}, source.stats)
  end

  defp merge_mix_audit(report, nil) do
    Report.put_source(report, %{name: "mix_audit", status: :not_included})
  end

  defp merge_mix_audit(report, path) do
    case MixAudit.load(path) do
      {:ok, findings} ->
        report
        |> Report.put_source(%{name: "mix_audit", status: :merged, findings: length(findings)})
        |> Report.add_findings(findings)

      {:error, message} ->
        report
        |> Report.add_findings([
          Finding.new(
            check: :mix_audit,
            kind: :operational,
            severity: :high,
            path: path,
            message: "cannot merge mix_audit report: #{message}"
          )
        ])
        |> Report.put_source(%{name: "mix_audit", status: :error, reason: message})
    end
  end

  defp apply_waivers(report, ctx) do
    findings = Enum.map(report.findings, &Policy.waive(ctx.policy, &1, ctx.today))
    notices = Enum.map(report.notices, &Policy.waive(ctx.policy, &1, ctx.today))
    %{report | findings: findings, notices: notices}
  end

  # -- render -----------------------------------------------------------------

  defp render(argv) do
    with {:ok, opts} <- parse(argv, @render_switches),
         {:ok, format} <- one_of(opts[:format] || "human", ~w(human json sarif), "--format"),
         {:ok, input} <- required(opts, :input),
         {:ok, report} <- JSON.load(input) do
      output = render_report(report, format, report_fail_on(report))
      write_or_print(output, opts[:output], 0)
    end
  end

  # Re-rendering must use the threshold the scan was run with, not the CLI
  # default, or a saved report can print PASS after failing at a lower threshold.
  defp report_fail_on(report) do
    value = report.inputs[:fail_on] || report.inputs["fail_on"] || "high"
    value = if is_atom(value), do: to_string(value), else: value

    case fail_on(value) do
      {:ok, threshold} -> threshold
      {:error, _message} -> :high
    end
  end

  defp render_and_finish(report, format, output_path, fail_on) do
    code = Report.exit_code(report, fail_on)
    output = render_report(report, format, fail_on)
    write_or_print(output, output_path, code)
  end

  defp render_report(report, "json", _fail_on), do: JSON.render(report)
  defp render_report(report, "sarif", _fail_on), do: SARIF.render(report)
  defp render_report(report, "human", fail_on), do: Human.render(report, fail_on: fail_on) <> "\n"

  defp write_or_print(output, nil, code), do: {:ok, output, code}

  defp write_or_print(output, path, code) do
    case File.write(path, output) do
      :ok -> {:ok, "", code}
      {:error, reason} -> {:error, "cannot write #{path}: #{:file.format_error(reason)}"}
    end
  end

  # -- options ----------------------------------------------------------------

  defp parse(argv, switches) do
    {opts, args, invalid} = OptionParser.parse(argv, strict: switches)

    cond do
      invalid != [] ->
        {:error, "invalid options: #{inspect(invalid)}"}

      args != [] ->
        {:error, "unexpected arguments: #{Enum.join(args, " ")}"}

      true ->
        {:ok, opts}
    end
  end

  defp one_of(value, allowed, label) do
    if value in allowed, do: {:ok, value}, else: {:error, "#{label} must be one of #{Enum.join(allowed, ", ")}"}
  end

  defp fail_on(value) do
    case value do
      "any" -> {:ok, :any}
      "low" -> {:ok, :low}
      "medium" -> {:ok, :medium}
      "high" -> {:ok, :high}
      "critical" -> {:ok, :critical}
      _ -> {:error, "--fail-on must be one of any, low, medium, high, critical"}
    end
  end

  defp today(nil), do: {:ok, Date.utc_today()}

  # Waiver expiry is judged against this date, so overriding it can make an
  # expired waiver look valid. It is for tests and replays only: it needs an
  # explicit environment opt-in, and the override is recorded in the report.
  defp today(value) do
    cond do
      System.get_env("DEP_GUARD_ALLOW_TODAY") != "1" ->
        {:error,
         "--today overrides the date used for waiver expiry and is for tests only; set DEP_GUARD_ALLOW_TODAY=1 to use it"}

      true ->
        case Date.from_iso8601(value) do
          {:ok, date} -> {:ok, date}
          {:error, _} -> {:error, "--today must be an ISO 8601 date (YYYY-MM-DD)"}
        end
    end
  end

  defp today_notice(nil), do: []

  defp today_notice(value) do
    [
      Finding.new(
        check: :policy,
        kind: :notice,
        severity: :info,
        message: "evaluation date overridden with --today #{value}; waiver expiry was judged against that date"
      )
    ]
  end

  defp exclusive(opts, left, right) do
    if opts[left] && opts[right] do
      {:error, "--#{dash(left)} and --#{dash(right)} cannot be used together"}
    else
      :ok
    end
  end

  defp required(opts, key) do
    case opts[key] do
      nil -> {:error, "--#{dash(key)} is required"}
      value -> {:ok, value}
    end
  end

  defp dash(key), do: key |> to_string() |> String.replace("_", "-")

  defp base_input(opts) do
    cond do
      opts[:base_lock] -> {:ok, {:file, Path.expand(opts[:base_lock])}}
      opts[:base_ref] -> base_ref(opts[:base_ref])
      true -> {:ok, nil}
    end
  end

  # The ref ends up in a `git show` argument; a leading dash would be read as an option.
  defp base_ref("-" <> _ = ref), do: {:error, "--base-ref #{inspect(ref)} must not start with a dash"}
  defp base_ref(ref), do: {:ok, {:ref, ref}}

  defp inputs(ctx, base, fail_on, opts) do
    %{
      lock_sha256: sha256(Path.join(ctx.root, "mix.lock")),
      fail_on: fail_on,
      evaluated_on: Date.to_iso8601(ctx.today),
      today_override: not is_nil(opts[:today]),
      allow_skipped: opts[:allow_skipped] == true
    }
    |> Map.merge(base_inputs(base))
  end

  defp base_inputs(nil), do: %{}

  defp base_inputs({:ref, ref}), do: %{base_ref: ref}

  defp base_inputs({:file, path}), do: %{base_lock_sha256: sha256(path)}

  defp sha256(path) do
    case File.read(path) do
      {:ok, contents} -> :crypto.hash(:sha256, contents) |> Base.encode16(case: :lower)
      {:error, _} -> nil
    end
  end

  # The runtime image has no git. CI sets the generic variables so the report
  # still records which revision was scanned.
  defp project_info(root) do
    %{
      root: root,
      repo: redact_url(git(root, ["config", "--get", "remote.origin.url"]) || env("DEP_GUARD_REPO")),
      commit: git(root, ["rev-parse", "HEAD"]) || env("DEP_GUARD_COMMIT"),
      branch: git(root, ["rev-parse", "--abbrev-ref", "HEAD"]) || env("DEP_GUARD_BRANCH")
    }
  end

  @doc """
  Removes `user:password@` from a URL. Remotes such as
  `https://ci-user:TOKEN@host/repo.git` carry credentials, and the report is
  uploaded as a CI artifact and as SARIF.
  """
  @spec redact_url(String.t() | nil) :: String.t() | nil
  def redact_url(nil), do: nil
  def redact_url(url) when is_binary(url), do: Regex.replace(~r{\A([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s]*@}, url, "\\1")

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      "" -> nil
      value -> value
    end
  end

  defp git(root, args) do
    case System.find_executable("git") do
      nil ->
        nil

      _git ->
        case System.cmd("git", args, cd: root, stderr_to_stdout: true) do
          {output, 0} -> output |> String.trim() |> blank_to_nil()
          _ -> nil
        end
    end
  end

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  defp usage do
    """
    dep_guard #{@version} — dependency scanner for Elixir projects

    Usage:
      dep_guard scan --root DIR [options]
      dep_guard render --input REPORT --format json|sarif|human [--output FILE]
      dep_guard version
      dep_guard help

    Scan options:
      --root DIR                 project root holding mix.lock (default: .)
      --org-policy FILE          org policy (authoritative)
      --org-policy-sha256 SHA    expected SHA-256 of the org policy
      --policy FILE              project waivers (default: DIR/.dep_guard.exs)
      --base-ref REF             compare mix.lock with git REF (needs git)
      --base-lock FILE           compare mix.lock with a saved base lock
      --mix-audit-report FILE    merge `mix deps.audit --format json`
      --format FORMAT            human (default), json, sarif
      --output FILE              write the report instead of stdout
      --fail-on LEVEL            any, low, medium, high (default), critical
      --offline                  skip the online sources (Hex API, EEF); the scan then
                                 exits 2 because advisory coverage is unproven
      --allow-skipped            accept skipped sources (only with --offline); the
                                 report records that you did
      --cache-dir DIR            HTTP cache (default: ~/.cache/dep_guard)
      --today YYYY-MM-DD         evaluation date, tests only: needs
                                 DEP_GUARD_ALLOW_TODAY=1 and is recorded in the report

    Exit codes:
      0  no unwaived findings at or above --fail-on
      1  security, integrity or policy findings
      2  operational error or incomplete scan (bad input, unreachable, skipped
         or uncovered source, policy mismatch)
      3  reserved for an unsupported environment (not emitted today)
    """
  end
end
