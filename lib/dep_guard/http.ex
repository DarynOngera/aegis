defmodule DepGuard.Http do
  @moduledoc false
  # Minimal HTTPS + JSON client on :httpc, so the scanner has no runtime deps.
  #
  # Returns a structured error (`status` is nil for transport errors) so callers
  # can decide what to retry. Headers such as authorization are never included in
  # error messages.

  @type headers :: [{String.t(), String.t()}]
  @type error :: %{status: integer() | nil, message: String.t()}

  @spec get_json(String.t(), headers()) :: {:ok, term()} | {:error, error()}
  def get_json(url, headers \\ []) do
    with {:ok, body} <- request(url, headers), do: decode(url, body)
  end

  defp request(url, headers) do
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)

    # No Accept header on purpose: cna.erlef.org answers per-record requests with
    # HTTP 406 when sent `Accept: application/json` (the .json path selects it).
    # hex.pm rejects requests without a User-Agent (HTTP 400).
    headers =
      headers
      |> Enum.reject(fn {key, _value} -> String.downcase(key) == "user-agent" end)
      |> then(&[{"user-agent", user_agent()} | &1])
      |> Enum.map(fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    req = {String.to_charlist(url), headers}

    case :httpc.request(:get, req, http_opts(), body_format: :binary) do
      {:ok, {{_, 200, _}, _headers, response}} ->
        {:ok, response}

      {:ok, {{_, status, _}, _headers, _response}} ->
        {:error, %{status: status, message: "GET #{url} returned HTTP #{status}"}}

      {:error, reason} ->
        {:error, %{status: nil, message: "GET #{url} failed: #{inspect(reason)}"}}
    end
  end

  defp http_opts do
    [
      timeout: 20_000,
      connect_timeout: 5_000,
      ssl: [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]
    ]
  end

  defp decode(url, body) do
    case JSON.decode(body) do
      {:ok, term} -> {:ok, term}
      {:error, reason} -> {:error, %{status: nil, message: "invalid JSON from #{url}: #{inspect(reason)}"}}
    end
  end

  defp user_agent do
    version = Application.spec(:dep_guard, :vsn) |> to_string_or_default()
    "dep_guard/#{version}"
  end

  defp to_string_or_default(nil), do: "0.2.0"
  defp to_string_or_default(value), do: to_string(value)
end
