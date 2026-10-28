defmodule DepGuard.CLITest do
  use ExUnit.Case, async: true

  alias DepGuard.CLI

  @checksum String.duplicate("a", 64)
  @outer String.duplicate("b", 64)

  setup do
    root = Path.join(System.tmp_dir!(), "dep_guard_cli_#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)

    File.write!(Path.join(root, "mix.exs"), """
    defmodule Demo.MixProject do
      use Mix.Project
      def project, do: [app: :demo, deps: [{:jason, "~> 1.4"}]]
    end
    """)

    write_lock(root, @checksum)

    on_exit(fn -> File.rm_rf(root) end)
    {:ok, root: root}
  end

  defp write_lock(root, checksum) do
    File.write!(Path.join(root, "mix.lock"), """
    %{
      "jason": {:hex, :jason, "1.4.4", "#{checksum}", [:mix], [], "hexpm", "#{@outer}"},
    }
    """)
  end

  defp scan(root, extra \\ []) do
    CLI.run(["scan", "--root", root, "--offline", "--today", "2026-10-24"] ++ extra)
  end

  test "a clean project passes and emits one JSON report", %{root: root} do
    assert {:ok, output, 0} = scan(root, ["--format", "json"])
    report = JSON.decode!(output)

    assert report["schema_version"] == "1.0"
    assert report["findings"] == []
    assert report["summary"]["total"] == 0
    assert %{"name" => "hex_api", "status" => "skipped"} = Enum.find(report["sources"], &(&1["name"] == "hex_api"))
    assert %{"name" => "eef", "status" => "skipped"} = Enum.find(report["sources"], &(&1["name"] == "eef"))

    assert %{"name" => "mix_audit", "status" => "not_included"} =
             Enum.find(report["sources"], &(&1["name"] == "mix_audit"))

    assert report["inputs"]["lock_sha256"] =~ ~r/^[0-9a-f]{64}$/
  end

  test "a merge failure is an error report, not a crash", %{root: root} do
    path = Path.join(root, "bad.json")
    File.write!(path, "{}")

    assert {:ok, output, 2} = scan(root, ["--format", "json", "--mix-audit-report", path])
    report = JSON.decode!(output)

    assert [%{"kind" => "operational", "check" => "mix_audit"}] = report["findings"]
  end

  test "mix_audit findings are merged and gated", %{root: root} do
    path = Path.join(root, "mix-audit.json")

    File.write!(path, """
    {"vulnerabilities": [
      {"dependency": {"package": "jason", "version": "1.4.4", "lockfile": "mix.lock"},
       "advisory": {"id": "GHSA-test-1", "title": "test", "severity": "low", "first_patched_versions": ["1.5.0"]}}
    ], "pass": false}
    """)

    assert {:ok, output, 0} = scan(root, ["--format", "json", "--mix-audit-report", path, "--fail-on", "high"])
    assert [%{"id" => "GHSA-test-1", "sources" => ["mix_audit"]}] = JSON.decode!(output)["findings"]

    assert {:ok, _output, 1} = scan(root, ["--format", "json", "--mix-audit-report", path, "--fail-on", "low"])
  end

  test "a checksum change against a base lock fails the gate", %{root: root} do
    base = Path.join(root, "base.lock")

    File.write!(base, """
    %{
      "jason": {:hex, :jason, "1.4.4", "#{String.duplicate("c", 64)}", [:mix], [], "hexpm", "#{@outer}"},
    }
    """)

    assert {:ok, output, 1} = scan(root, ["--format", "json", "--base-lock", base])
    assert [%{"check" => "lock_changes", "kind" => "integrity"}] = JSON.decode!(output)["findings"]
  end

  test "an invalid option or policy is a clear error", %{root: root} do
    assert {:error, message} = scan(root, ["--fail-on", "nonsense"])
    assert message =~ "--fail-on"

    File.write!(Path.join(root, ".dep_guard.exs"), ~s|%{allowed_repos: ["hexpm:evil"]}|)
    assert {:error, message} = scan(root)
    assert message =~ "unknown keys"
  end

  test "project waivers apply to merged findings and the org hash is recorded", %{root: root} do
    org = Path.join(root, "org.exs")
    File.write!(org, ~s|%{allowed_repos: ["hexpm"], max_ignore_days: 90}|)
    org_sha = :crypto.hash(:sha256, File.read!(org)) |> Base.encode16(case: :lower)

    File.write!(Path.join(root, ".dep_guard.exs"), """
    %{
      ignore_advisories: [
        %{id: "GHSA-test-1", package: "jason", reason: "not reachable", expires: "2026-12-01"}
      ]
    }
    """)

    audit = Path.join(root, "mix-audit.json")

    File.write!(audit, """
    {"vulnerabilities": [
      {"dependency": {"package": "jason", "version": "1.4.4", "lockfile": "mix.lock"},
       "advisory": {"id": "GHSA-test-1", "title": "test", "severity": "high", "first_patched_versions": ["1.5.0"]}}
    ], "pass": false}
    """)

    assert {:ok, output, 0} =
             scan(root, [
               "--format",
               "json",
               "--mix-audit-report",
               audit,
               "--org-policy",
               org,
               "--org-policy-sha256",
               org_sha
             ])

    report = JSON.decode!(output)
    assert report["policy"]["org_sha256"] == org_sha
    assert report["summary"]["waived"] == 1
    assert [%{"waived" => true, "waiver" => %{"reason" => "not reachable"}}] = report["findings"]
  end

  test "a policy hash mismatch is a clear error", %{root: root} do
    org = Path.join(root, "org.exs")
    File.write!(org, ~s|%{allowed_repos: ["hexpm"]}|)

    assert {:error, message} =
             scan(root, ["--org-policy", org, "--org-policy-sha256", String.duplicate("0", 64)])

    assert message =~ "SHA-256"
  end

  test "SARIF can be written and re-rendered from JSON without a scan", %{root: root} do
    json_path = Path.join(root, "report.json")
    sarif_path = Path.join(root, "report.sarif")

    assert {:ok, "", 0} = scan(root, ["--format", "json", "--output", json_path])
    assert File.exists?(json_path)

    assert {:ok, "", 0} =
             CLI.run(["render", "--input", json_path, "--format", "sarif", "--output", sarif_path])

    sarif = sarif_path |> File.read!() |> JSON.decode!()
    assert sarif["version"] == "2.1.0"
    assert [%{"tool" => %{"driver" => %{"name" => "dep_guard"}}}] = sarif["runs"]
  end

  test "malformed saved report data is an error, not a crash", %{root: root} do
    path = Path.join(root, "broken.json")
    File.write!(path, ~s({"schema_version":"1.0","findings":"not-a-list"}))

    assert {:error, message} = CLI.run(["render", "--input", path])
    assert message =~ "unexpected error"

    File.write!(path, ~s({"schema_version":"1.0","sources":{"hex_api":"ok"}}))
    assert {:error, _message} = CLI.run(["render", "--input", path])
  end

  test "human output reports source coverage", %{root: root} do
    assert {:ok, output, 0} = scan(root, ["--fail-on", "high"])
    assert output =~ "dep_guard 0.2.0"
    assert output =~ "hex_api: skipped"
    assert output =~ "mix_audit: not_included"
    assert output =~ "PASS"
  end

  test "the CLI version matches mix.exs" do
    assert {:ok, output, 0} = CLI.run(["version"])
    assert output == "dep_guard #{Mix.Project.config()[:version]}\n"
  end

  test "rendering uses the fail threshold saved in the report", %{root: root} do
    audit = Path.join(root, "mix-audit.json")

    File.write!(audit, """
    {"vulnerabilities": [
      {"dependency": {"package": "jason", "version": "1.4.4", "lockfile": "mix.lock"},
       "advisory": {"id": "GHSA-low-1", "title": "low", "severity": "low", "first_patched_versions": ["1.5.0"]}}
    ], "pass": false}
    """)

    json_path = Path.join(root, "report.json")

    assert {:ok, "", 1} =
             scan(root, [
               "--format",
               "json",
               "--output",
               json_path,
               "--mix-audit-report",
               audit,
               "--fail-on",
               "low"
             ])

    assert {:ok, human, 0} = CLI.run(["render", "--input", json_path])
    assert human =~ "FAIL — unwaived findings at or above low"
  end
end
