defmodule DepGuard.Http do
  @moduledoc false
  # Minimal HTTPS + JSON client on :httpc, so the library has no runtime dependencies.
  # Needs OTP 25+ (`:public_key.cacerts_get/0`) and Elixir 1.18+ (built-in `JSON`) or `:jason`.
  #
  # Headers passed in (e.g. authorization) are never included in error messages.

  @type headers :: [{String.t(), String.t()}]

  @spec get_json(String.t(), headers()) :: {:ok, term()} | {:error, String.t()}
  def get_json(url, headers \\ []) do
    with {:ok, body} <- request(:get, url, headers, nil), do: decode(url, body)
  end

  @spec post_json(String.t(), term(), headers()) :: {:ok, term()} | {:error, String.t()}
  def post_json(url, payload, headers \\ []) do
    with {:ok, json} <- encode(payload),
         {:ok, body} <- request(:post, url, headers, json),
         do: decode(url, body)
  end

  defp request(method, url, headers, body) do
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)

    headers =
      [{~c"accept", ~c"application/json"}] ++
        Enum.map(headers, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    req =
      case method do
        :get -> {String.to_charlist(url), headers}
        :post -> {String.to_charlist(url), headers, ~c"application/json", body}
      end

    case :httpc.request(method, req, http_opts(), body_format: :binary) do
      {:ok, {{_, 200, _}, _headers, response}} ->
        {:ok, response}

      {:ok, {{_, status, _}, _headers, _response}} when status in [401, 403] ->
        {:error, "#{method |> to_string() |> String.upcase()} #{url} returned HTTP #{status} (check the token)"}

      {:ok, {{_, status, _}, _headers, _response}} ->
        {:error, "#{method |> to_string() |> String.upcase()} #{url} returned HTTP #{status}"}

      {:error, reason} ->
        {:error, "#{method |> to_string() |> String.upcase()} #{url} failed: #{inspect(reason)}"}
    end
  end

  defp http_opts do
    [
      timeout: 20_000,
      ssl: [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]
    ]
  end

  defp decode(url, body) do
    with {:ok, decode} <- json_fun(:decode, 1) do
      case decode.(body) do
        {:ok, term} -> {:ok, term}
        {:error, reason} -> {:error, "invalid JSON from #{url}: #{inspect(reason)}"}
      end
    end
  end

  defp encode(term) do
    with {:ok, encode} <- json_fun(:encode!, 1), do: {:ok, encode.(term)}
  end

  defp json_fun(name, arity) do
    cond do
      Code.ensure_loaded?(JSON) -> {:ok, Function.capture(JSON, name, arity)}
      Code.ensure_loaded?(Jason) -> {:ok, Function.capture(Jason, name, arity)}
      true -> {:error, "no JSON library: need Elixir 1.18+ (built-in JSON) or the :jason package"}
    end
  end
end
