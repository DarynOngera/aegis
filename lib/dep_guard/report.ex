defmodule DepGuard.Report do
  @moduledoc """
  The single result of one scan.

  Everything the CLI prints or writes is a rendering of this struct. JSON is the
  canonical form; SARIF and human output are projections of the same report.

  A source is recorded even when it found nothing. `status: :error` or
  `status: :uncovered` means the check did not complete, and the report must not
  be read as clean.
  """

  alias DepGuard.Finding

  @schema_version "1.0"
  @default_version "0.2.0"

  defstruct schema_version: @schema_version,
            tool: %{},
            run: %{},
            project: %{},
            policy: %{},
            inputs: %{},
            sources: [],
            findings: [],
            notices: [],
            summary: %{}

  @type source :: map()

  @type t :: %__MODULE__{
          schema_version: String.t(),
          tool: map(),
          run: map(),
          project: map(),
          policy: map(),
          inputs: map(),
          sources: [source()],
          findings: [Finding.t()],
          notices: [Finding.t()],
          summary: map()
        }

  @doc "Starts a report for one run."
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())

    %__MODULE__{
      tool: %{
        name: "dep_guard",
        version: Keyword.get(opts, :version, version()),
        image_digest: Keyword.get(opts, :image_digest)
      },
      run: %{
        id: Keyword.get(opts, :run_id, run_id()),
        started_at: DateTime.to_iso8601(now),
        duration_ms: nil
      },
      project: Map.new(Keyword.get(opts, :project, %{})),
      policy: Map.new(Keyword.get(opts, :policy, %{})),
      inputs: Map.new(Keyword.get(opts, :inputs, %{}))
    }
  end

  @doc "Records or replaces a source entry by name."
  @spec put_source(t(), source()) :: t()
  def put_source(%__MODULE__{} = report, %{name: name} = source) do
    sources = Enum.reject(report.sources, &(&1.name == name))
    %{report | sources: sources ++ [source]}
  end

  @doc "Adds findings; `:notice` findings are kept separate from gating findings."
  @spec add_findings(t(), [Finding.t()]) :: t()
  def add_findings(%__MODULE__{} = report, findings) when is_list(findings) do
    {notices, gating} = Enum.split_with(findings, &(&1.kind == :notice))
    %{report | findings: report.findings ++ gating, notices: report.notices ++ notices}
  end

  @doc "Deduplicates findings for the same package and version that share any advisory ID or alias."
  @spec dedupe(t()) :: t()
  def dedupe(%__MODULE__{} = report) do
    findings =
      report.findings
      |> Enum.reduce([], &merge_into_groups/2)
      |> Enum.sort_by(&{-Finding.rank(&1.severity), &1.package || "", &1.id || &1.message})

    %{report | findings: findings, notices: dedupe_notices(report.notices)}
  end

  # One advisory can reach us from several sources with different primary IDs
  # (for example EEF-CVE-2025-4754 and GHSA-f7gq-h8jv-h3cq). A shared ID or
  # alias means the same advisory, so the groups merge transitively.
  # Findings for different packages or versions stay separate even when one
  # advisory lists them both: they are distinct things to fix.
  defp merge_into_groups(finding, groups) do
    case Enum.split_with(groups, &related?(&1, finding)) do
      {[], _others} ->
        [finding | groups]

      {[group | rest], others} ->
        merged = Enum.reduce([finding | rest], group, fn item, acc -> Finding.merge(acc, item) end)
        [merged | others]
    end
  end

  defp related?(left, right) do
    left.package == right.package and left.version == right.version and
      not MapSet.disjoint?(MapSet.new(tokens(left)), MapSet.new(tokens(right)))
  end

  defp tokens(%Finding{} = finding) do
    if is_binary(finding.id) and finding.id != "" do
      Enum.uniq([finding.id | finding.aliases])
    else
      [Finding.key(finding)]
    end
  end

  defp dedupe_notices(notices) do
    notices
    |> Enum.uniq_by(&{&1.check, &1.message})
    |> Enum.sort_by(& &1.message)
  end

  @doc "Stamps duration and computes summary counts."
  @spec finalize(t(), keyword()) :: t()
  def finalize(%__MODULE__{} = report, opts \\ []) do
    duration = Keyword.get(opts, :duration_ms)

    report = %{
      report
      | run: Map.put(report.run, :duration_ms, duration),
        summary: summary(report.findings, report.notices)
    }

    report
  end

  defp summary(findings, notices) do
    counts =
      Enum.reduce(findings, %{critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0}, fn finding, acc ->
        Map.update!(acc, finding.severity, &(&1 + 1))
      end)

    counts
    |> Map.put(:total, length(findings))
    |> Map.put(:waived, Enum.count(findings, & &1.waived))
    |> Map.put(:notices, length(notices))
  end

  @doc """
  Exit code for the gate:

    * `2` when any operational finding exists or a source did not complete
      (`error` / `uncovered`), because the scan did not finish
    * `2` when a source was `skipped` (for example by `--offline`), because the
      report then proves nothing about advisories, unless the scan was run with
      `--allow-skipped` (recorded in `inputs.allow_skipped`)
    * `1` when any unwaived finding is at or above the threshold
    * `0` otherwise
  """
  @spec exit_code(t(), :any | :low | :medium | :high | :critical) :: 0 | 1 | 2
  def exit_code(%__MODULE__{} = report, threshold) do
    incomplete = if allow_skipped?(report), do: ["error", "uncovered"], else: ["error", "uncovered", "skipped"]

    cond do
      Enum.any?(report.findings, &(&1.kind == :operational)) -> 2
      Enum.any?(report.sources, &(source_status(&1) in incomplete)) -> 2
      Enum.any?(report.findings, &Finding.gating?(&1, threshold)) -> 1
      true -> 0
    end
  end

  # Inputs are atom-keyed in memory and string-keyed after a JSON round trip.
  defp allow_skipped?(%__MODULE__{inputs: inputs}) do
    inputs[:allow_skipped] == true or inputs["allow_skipped"] == true
  end

  # Sources are maps in memory (atom status) and after a JSON round-trip
  # (string status); accept both.
  defp source_status(source) do
    case source[:status] || source["status"] do
      nil -> nil
      value -> to_string(value)
    end
  end

  @doc "Plain map suitable for JSON encoding."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = report) do
    %{
      schema_version: report.schema_version,
      tool: report.tool,
      run: report.run,
      project: report.project,
      policy: report.policy,
      inputs: report.inputs,
      sources: Enum.map(report.sources, &source_map/1),
      findings: Enum.map(report.findings, &finding_map/1),
      notices: Enum.map(report.notices, &finding_map/1),
      summary: report.summary
    }
  end

  defp source_map(source) do
    Map.update(source, :status, nil, &to_string/1)
  end

  defp finding_map(%Finding{} = f) do
    %{
      id: f.id,
      check: to_string(f.check),
      kind: to_string(f.kind),
      severity: to_string(f.severity),
      package: f.package,
      version: f.version,
      aliases: f.aliases,
      sources: f.sources,
      message: f.message,
      remediation: f.remediation,
      path: f.path,
      waived: not is_nil(f.waived),
      waiver: waiver_map(f.waived)
    }
  end

  defp waiver_map(nil), do: nil

  defp waiver_map(waiver) do
    %{reason: Map.get(waiver, :reason), expires: Map.get(waiver, :expires)}
  end

  defp run_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp version do
    case Application.spec(:dep_guard, :vsn) do
      nil -> @default_version
      vsn -> to_string(vsn)
    end
  end
end
