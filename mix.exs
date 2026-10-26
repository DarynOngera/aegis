defmodule DepGuard.MixProject do
  use Mix.Project

  def project do
    [
      app: :dep_guard,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: false,
      deps: [],
      description:
        "ExUnit suite that audits an Elixir project's dependencies: retirements, " <>
          "advisories, lockfile integrity, sources and tampering."
    ]
  end

  def application do
    [extra_applications: [:logger, :mix, :ex_unit, :inets, :ssl, :public_key]]
  end
end
