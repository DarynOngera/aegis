defmodule DepGuard.TestHttp do
  @moduledoc false
  # Tiny HTTP/1.1 server for tests. No external dependencies.

  @spec start(map() | (String.t() -> {integer(), String.t()})) :: %{url: String.t(), socket: port()}
  def start(routes) do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(socket)

    pid =
      spawn_link(fn ->
        receive do
          :go -> accept_loop(socket, routes)
        end
      end)

    :ok = :gen_tcp.controlling_process(socket, pid)
    send(pid, :go)
    %{url: "http://127.0.0.1:#{port}", socket: socket}
  end

  def stop(%{socket: socket}), do: :gen_tcp.close(socket)

  defp accept_loop(socket, routes) do
    case :gen_tcp.accept(socket) do
      {:ok, conn} ->
        pid = spawn(fn -> serve(conn, routes) end)
        :gen_tcp.controlling_process(conn, pid)
        send(pid, :go)
        accept_loop(socket, routes)

      {:error, _reason} ->
        :ok
    end
  end

  defp serve(conn, routes) do
    receive do
      :go -> :ok
    after
      1_000 -> :ok
    end

    case read_request(conn) do
      {:ok, path} ->
        {status, body} = route(routes, path)
        send_response(conn, status, body)

      :error ->
        :ok
    end

    :gen_tcp.close(conn)
  end

  defp read_request(conn, acc \\ "") do
    if String.contains?(acc, "\r\n\r\n") do
      [line | _] = String.split(acc, "\r\n")
      {:ok, line |> String.split(" ") |> Enum.at(1)}
    else
      case :gen_tcp.recv(conn, 0, 5_000) do
        {:ok, data} -> read_request(conn, acc <> data)
        {:error, _} -> :error
      end
    end
  end

  defp route(routes, path) when is_function(routes, 1), do: routes.(path)

  defp route(routes, path) do
    case Map.fetch(routes, path) do
      {:ok, {_status, _body} = response} -> response
      {:ok, body} when is_binary(body) -> {200, body}
      :error -> {404, ~s({"error":"not found"})}
    end
  end

  defp send_response(conn, status, body) do
    response =
      "HTTP/1.1 #{status} #{reason(status)}\r\n" <>
        "Content-Type: application/json\r\n" <>
        "Content-Length: #{byte_size(body)}\r\n" <>
        "Connection: close\r\n\r\n" <> body

    :gen_tcp.send(conn, response)
  end

  defp reason(200), do: "OK"
  defp reason(401), do: "Unauthorized"
  defp reason(403), do: "Forbidden"
  defp reason(404), do: "Not Found"
  defp reason(429), do: "Too Many Requests"
  defp reason(500), do: "Internal Server Error"
  defp reason(status), do: Integer.to_string(status)
end
