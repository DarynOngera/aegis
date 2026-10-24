defmodule Mix.Tasks.DepGuard.Eef do
  use Mix.Task

  @shortdoc "Queries the EEF CNA GraphQL API (schema | cves)"

  @moduledoc """
  Talks to the EEF CNA GraphQL API using the token in `EEF_CNA_TOKEN`.

      mix dep_guard.eef schema   # introspect: list types and fields (use this to see what can be matched)
      mix dep_guard.eef cves     # list published CVE ids and titles
  """

  alias DepGuard.EefGraphQL

  @impl Mix.Task
  def run(["schema"]), do: print(EefGraphQL.introspect())
  def run(["cves"]), do: print(EefGraphQL.published_cves())
  def run(_other), do: Mix.raise("usage: mix dep_guard.eef schema | cves")

  defp print({:ok, data}), do: IO.puts(inspect(data, pretty: true, limit: :infinity, printable_limit: :infinity))
  defp print({:error, message}), do: Mix.raise(message)
end
