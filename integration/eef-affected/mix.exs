defmodule Integration.EefAffected.MixProject do
  use Mix.Project

  def project do
    [app: :integration_eef_affected, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
  end

  def application, do: [extra_applications: [:logger]]

  # 2.9.0 is affected by EEF-CVE-2025-4754 (fixed in 2.10.0).
  defp deps do
    [{:ash_authentication_phoenix, "~> 2.9.0"}]
  end
end
