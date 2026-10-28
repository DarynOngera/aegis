defmodule DepGuard.MixAuditTest do
  use ExUnit.Case, async: true

  alias DepGuard.MixAudit

  defp write(contents) do
    path = Path.join(System.tmp_dir!(), "dep_guard_mix_audit_#{System.unique_integer([:positive])}.json")
    File.write!(path, contents)
    on_exit(fn -> File.rm(path) end)
    path
  end

  test "normalises a mix_audit JSON report" do
    path =
      write("""
      {
        "vulnerabilities": [
          {
            "dependency": {"package": "sweet_xml", "version": "0.6.6", "lockfile": "mix.lock"},
            "advisory": {
              "id": "GHSA-qpmc-wprv-x746",
              "title": "Inline DTD allows XML bomb attack",
              "severity": "high",
              "first_patched_versions": ["0.7.0"]
            }
          }
        ],
        "pass": false
      }
      """)

    assert {:ok, [finding]} = MixAudit.load(path)
    assert finding.id == "GHSA-qpmc-wprv-x746"
    assert finding.check == :mix_audit
    assert finding.sources == ["mix_audit"]
    assert finding.severity == :high
    assert finding.remediation =~ "0.7.0"
  end

  test "a malformed report is an error, not a partial merge" do
    assert {:error, message} = MixAudit.load(write(~s({"pass": true})))
    assert message =~ "vulnerabilities"

    assert {:error, message} =
             MixAudit.load(write(~s({"vulnerabilities": [{"dependency": {"package": "x"}}]})))

    assert message =~ "vulnerability"

    assert {:error, message} = MixAudit.load(write(~s({"vulnerabilities": [], "pass": false})))
    assert message =~ "pass is false"
  end

  test "invalid JSON is an error" do
    assert {:error, message} = MixAudit.load(write("{"))
    assert message =~ "invalid JSON"
  end
end
