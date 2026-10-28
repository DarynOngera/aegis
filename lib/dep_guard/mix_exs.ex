defmodule DepGuard.MixExs do
  @moduledoc """
  Reads `mix.exs` as an AST and looks for Hex ignore configuration.

  The file is never evaluated: a project's `mix.exs` is arbitrary code, and the
  scanner must not run it. If the `hex:` option is computed rather than written
  as a literal, the scanner reports that it cannot inspect it instead of assuming
  it is empty.
  """

  alias DepGuard.Finding

  @ignore_keys [:ignore_advisories, :ignore_retirements]

  @spec scan(Path.t()) :: {:ok, [Finding.t()]} | {:error, String.t()}
  def scan(path) do
    case File.read(path) do
      {:ok, source} -> parse(path, source)
      {:error, :enoent} -> {:error, "#{path} not found"}
      {:error, reason} -> {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  defp parse(path, source) do
    case Code.string_to_quoted(source) do
      {:ok, ast} -> {:ok, findings(ast, path)}
      {:error, _error} -> {:error, "#{path} does not parse"}
    end
  end

  defp findings(ast, path) do
    ast
    |> project_body()
    |> hex_values()
    |> Enum.flat_map(&ignore_findings(&1, path))
  end

  defp project_body(ast) do
    {_ast, body} =
      Macro.prewalk(ast, nil, fn
        {:def, _, [{:project, _, _}, [do: body]]} = node, nil -> {node, body}
        node, acc -> {node, acc}
      end)

    body
  end

  # Collects the value AST of every `hex:` key in the project keyword list.
  defp hex_values(nil), do: []

  defp hex_values({:__block__, _, expressions}), do: Enum.flat_map(expressions, &hex_values/1)
  defp hex_values(list) when is_list(list), do: for({:hex, value} <- list, do: value)
  defp hex_values(_other), do: []

  defp ignore_findings(value, path) when is_list(value) do
    for key <- @ignore_keys, {^key, setting} <- value, non_empty?(setting) do
      Finding.new(
        check: :mix_exs,
        kind: :policy,
        severity: :high,
        path: path,
        message: "mix.exs sets hex: [#{key}: ...]. Move it to .dep_guard.exs so it needs a reason and an expiry."
      )
    end
  end

  defp ignore_findings(value, path) do
    # A computed value could contain ignore lists. Refuse to guess.
    if dynamic?(value) do
      [
        Finding.new(
          check: :mix_exs,
          kind: :policy,
          severity: :high,
          path: path,
          message:
            "mix.exs computes its hex: configuration, so hex ignore lists cannot be inspected. " <>
              "Write the option as a literal or remove it."
        )
      ]
    else
      []
    end
  end

  defp non_empty?(nil), do: false
  defp non_empty?([]), do: false
  defp non_empty?(_value), do: true

  defp dynamic?(nil), do: false
  defp dynamic?(value) when is_atom(value) or is_binary(value) or is_number(value), do: false
  defp dynamic?(value) when is_list(value), do: false
  defp dynamic?({:%{}, _, _}), do: false
  defp dynamic?(_value), do: true
end
