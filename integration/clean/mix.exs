defmodule Integration.Clean.MixProject do
  use Mix.Project

  def project do
    [app: :integration_clean, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [{:jason, "~> 1.4"}]
  end
end
