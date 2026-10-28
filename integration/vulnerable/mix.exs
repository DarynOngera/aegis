defmodule Integration.Vulnerable.MixProject do
  use Mix.Project

  def project do
    [app: :integration_vulnerable, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
  end

  def application, do: [extra_applications: [:logger]]

  # sweet_xml 0.6.6 is affected by GHSA-qpmc-wprv-x746 (CVE-2019-15160).
  defp deps do
    [{:sweet_xml, "~> 0.6.6"}]
  end
end
