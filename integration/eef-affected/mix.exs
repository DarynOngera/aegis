defmodule Integration.MixProject do
  use Mix.Project

  def project, do: [app: :integration, version: "0.0.0", elixir: "~> 1.16", deps: deps()]
  def application, do: [extra_applications: [:logger]]

  defp deps do
    [
      {:ash_authentication_phoenix, "2.9.0"},
      {:dep_guard, path: "../..", only: :test, runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
    ]
  end
end
