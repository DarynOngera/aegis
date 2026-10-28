defmodule DepGuard.MixProject do
  use Mix.Project

  @version "0.2.0"

  def project do
    [
      app: :dep_guard,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: false,
      deps: [],
      elixirc_paths: elixirc_paths(Mix.env()),
      escript: [main_module: DepGuard.CLI],
      releases: [
        dep_guard: [
          include_executables_for: [:unix],
          strip_beams: true
        ]
      ],
      description:
        "Standalone dependency scanner for Elixir projects: retirements, " <>
          "advisories, lockfile integrity, sources and tampering."
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :inets, :ssl, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]
end
