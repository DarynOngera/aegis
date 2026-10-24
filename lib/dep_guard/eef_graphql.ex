defmodule DepGuard.EefGraphQL do
  @moduledoc """
  Client for the EEF CNA GraphQL API (`https://cna.erlef.org/gql`).

  The token is read from the `EEF_CNA_TOKEN` environment variable (use a CI secret) and is
  only ever sent as a bearer header; it is never logged or included in errors.

  Only `published_cves/1` (the query from the EEF's own example) and `introspect/1` are
  implemented. Matching CVEs against a lockfile needs the affected-package fields, which
  are not part of the verified query. Run `mix dep_guard.eef schema` with a token to
  list the real fields, then extend `published_cves/1` with them.
  """

  alias DepGuard.Http

  @default_endpoint "https://cna.erlef.org/gql"

  @published_cves "{ listPublishedCves { results { cveId title } } }"

  @introspection """
  { __schema { queryType { name } types { name kind
      fields { name type { name kind ofType { name kind } } } } } }
  """

  @spec published_cves(keyword()) :: {:ok, [map()]} | {:error, String.t()}
  def published_cves(opts \\ []) do
    with {:ok, data} <- run(@published_cves, opts) do
      case get_in(data, ["listPublishedCves", "results"]) do
        list when is_list(list) -> {:ok, list}
        other -> {:error, "unexpected response shape for listPublishedCves: #{inspect(other)}"}
      end
    end
  end

  @spec introspect(keyword()) :: {:ok, map()} | {:error, String.t()}
  def introspect(opts \\ []), do: run(@introspection, opts)

  @spec run(String.t(), keyword()) :: {:ok, map()} | {:error, String.t()}
  def run(query, opts \\ []) do
    endpoint = Keyword.get(opts, :endpoint, @default_endpoint)

    with {:ok, token} <- token(opts),
         {:ok, response} <-
           Http.post_json(endpoint, %{"query" => query}, [{"authorization", "Bearer " <> token}]) do
      case response do
        %{"errors" => [_ | _] = errors} ->
          {:error, "GraphQL errors: " <> Enum.map_join(errors, "; ", &(&1["message"] || inspect(&1)))}

        %{"data" => %{} = data} ->
          {:ok, data}

        other ->
          {:error, "unexpected GraphQL response: #{inspect(other, limit: 5)}"}
      end
    end
  end

  defp token(opts) do
    case Keyword.get(opts, :token) || System.get_env("EEF_CNA_TOKEN") do
      nil -> {:error, "EEF_CNA_TOKEN is not set"}
      "" -> {:error, "EEF_CNA_TOKEN is empty"}
      token -> {:ok, token}
    end
  end
end
