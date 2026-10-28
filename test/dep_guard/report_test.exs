defmodule DepGuard.ReportTest do
  use ExUnit.Case, async: true

  alias DepGuard.{Finding, Report}
  alias DepGuard.Report.{JSON, SARIF}

  defp finding(attrs) do
    Finding.new(Map.merge(%{check: :advisories, kind: :security, severity: :high, message: "x"}, Map.new(attrs)))
  end

  test "dedupe collapses the same advisory from several sources" do
    report =
      Report.new(version: "0.2.0")
      |> Report.add_findings([
        finding(id: "GHSA-1", severity: :medium, sources: ["hex_api"], aliases: ["CVE-1"]),
        finding(id: "GHSA-1", severity: :high, sources: ["mix_audit"], aliases: ["CVE-1"]),
        finding(id: "GHSA-2", severity: :low, sources: ["eef"])
      ])
      |> Report.dedupe()

    assert length(report.findings) == 2
    merged = Enum.find(report.findings, &(&1.id == "GHSA-1"))
    assert merged.severity == :high
    assert merged.sources == ["hex_api", "mix_audit"]
  end

  test "dedupe merges findings that share an alias" do
    report =
      Report.new(version: "0.2.0")
      |> Report.add_findings([
        finding(
          id: "EEF-CVE-2025-4754",
          severity: :high,
          package: "ash_authentication_phoenix",
          aliases: ["GHSA-f7gq-h8jv-h3cq", "CVE-2025-4754"],
          sources: ["eef"]
        ),
        finding(
          id: "GHSA-f7gq-h8jv-h3cq",
          severity: :low,
          package: "ash_authentication_phoenix",
          aliases: ["CVE-2025-4754"],
          sources: ["hex_api"]
        )
      ])
      |> Report.dedupe()

    assert [merged] = report.findings
    assert merged.severity == :high
    assert Enum.sort(merged.sources) == ["eef", "hex_api"]
    assert merged.aliases == ["GHSA-f7gq-h8jv-h3cq", "CVE-2025-4754"]
  end

  test "dedupe keeps one advisory on different packages separate" do
    report =
      Report.new(version: "0.2.0")
      |> Report.add_findings([
        finding(id: "GHSA-shared", package: "plug", version: "1.0.0", sources: ["hex_api"]),
        finding(id: "GHSA-shared", package: "phoenix", version: "1.0.0", sources: ["hex_api"])
      ])
      |> Report.dedupe()

    assert [_, _] = report.findings
    assert report.findings |> Enum.map(& &1.package) |> Enum.sort() == ["phoenix", "plug"]
  end

  test "human output counts critical findings" do
    report =
      Report.new()
      |> Report.add_findings([finding(severity: :critical, message: "boom")])
      |> Report.finalize()

    assert Report.Human.render(report, fail_on: :critical) =~ "1 critical, 0 high, 0 medium, 0 low"
  end

  test "notices are kept out of the gating findings" do
    report =
      Report.new()
      |> Report.add_findings([finding(kind: :notice, severity: :info, message: "new dep")])
      |> Report.finalize()

    assert report.findings == []
    assert length(report.notices) == 1
    assert report.summary.notices == 1
  end

  test "exit codes: clean, findings, operational" do
    clean = Report.finalize(Report.new())
    assert Report.exit_code(clean, :high) == 0

    medium = Report.finalize(Report.new() |> Report.add_findings([finding(severity: :medium)]))
    assert Report.exit_code(medium, :high) == 0
    assert Report.exit_code(medium, :medium) == 1

    waived =
      Report.finalize(
        Report.new()
        |> Report.add_findings([finding(severity: :high, waived: %{reason: "r", expires: "2026-12-01"})])
      )

    assert Report.exit_code(waived, :high) == 0

    operational =
      Report.finalize(Report.new() |> Report.add_findings([finding(kind: :operational, severity: :high)]))

    assert Report.exit_code(operational, :critical) == 2

    incomplete =
      Report.finalize(Report.new() |> Report.put_source(%{name: "hex_api", status: :error}))

    assert Report.exit_code(incomplete, :high) == 2
  end

  test "JSON renderer round-trips through the loader" do
    report =
      Report.new(version: "0.2.0", project: %{root: "/tmp/x"})
      |> Report.add_findings([finding(id: "GHSA-1", package: "sweet_xml", version: "0.6.6", aliases: ["CVE-1"])])
      |> Report.put_source(%{name: "hex_api", status: :ok, requests: 1})
      |> Report.finalize()

    json = JSON.render(report)
    path = Path.join(System.tmp_dir!(), "dep_guard_report_#{System.unique_integer([:positive])}.json")
    File.write!(path, json)
    on_exit(fn -> File.rm(path) end)

    assert {:ok, loaded} = JSON.load(path)
    assert loaded.schema_version == "1.0"
    assert [%{id: "GHSA-1", package: "sweet_xml", sources: []}] = loaded.findings
    assert [%{name: "hex_api", status: "ok"}] = loaded.sources
  end

  test "SARIF renderer emits 2.1.0 with rules and levels" do
    report =
      Report.new(version: "0.2.0")
      |> Report.add_findings([
        finding(id: "GHSA-1", package: "sweet_xml", version: "0.6.6", path: "mix.lock"),
        finding(id: "GHSA-2", severity: :medium, path: "mix.lock")
      ])
      |> Report.finalize()

    sarif = SARIF.to_map(report)
    assert sarif["$schema"] =~ "sarif"
    assert sarif.version == "2.1.0"
    [run] = sarif.runs
    assert run.tool.driver.name == "dep_guard"
    assert run.tool.driver.rules != []
    assert Enum.map(run.results, & &1.level) == ["error", "warning"]

    assert hd(run.results).locations == [
             %{physicalLocation: %{artifactLocation: %{uri: "mix.lock"}, region: %{startLine: 1}}}
           ]
  end

  test "a skipped source makes the gate incomplete unless the scan allowed it" do
    skipped = Report.new() |> Report.put_source(%{name: "hex_api", status: :skipped}) |> Report.finalize()
    assert Report.exit_code(skipped, :high) == 2

    allowed =
      Report.new(inputs: %{allow_skipped: true})
      |> Report.put_source(%{name: "hex_api", status: :skipped})
      |> Report.finalize()

    assert Report.exit_code(allowed, :high) == 0

    # an error or uncovered source is never excused by allow_skipped
    broken =
      Report.new(inputs: %{allow_skipped: true})
      |> Report.put_source(%{name: "hex_api", status: :error})
      |> Report.finalize()

    assert Report.exit_code(broken, :high) == 2

    # the flag survives a JSON round trip (string keys)
    round_trip = %{
      allowed
      | inputs: %{"allow_skipped" => true},
        sources: [%{"name" => "hex_api", "status" => "skipped"}]
    }

    assert Report.exit_code(round_trip, :high) == 0
  end

  test "SARIF marks waived findings as suppressed with the waiver reason" do
    waived = %{reason: "not reachable", expires: "2026-12-01"}

    report =
      Report.new(version: "0.2.0")
      |> Report.add_findings([
        finding(id: "GHSA-1", package: "a", path: "mix.lock", waived: waived),
        finding(id: "GHSA-2", package: "b", path: "mix.lock")
      ])
      |> Report.finalize()

    [run] = SARIF.to_map(report).runs
    [suppressed, open] = run.results

    assert [%{kind: "external", status: "accepted", justification: justification}] = suppressed.suppressions
    assert justification == "waived until 2026-12-01: not reachable"
    refute Map.has_key?(open, :suppressions)
  end
end
