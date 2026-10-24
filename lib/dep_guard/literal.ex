defmodule DepGuard.Literal do
  @moduledoc false
  # Parses Elixir source that must consist only of data literals (atoms, numbers,
  # strings, lists, tuples, maps) and evaluates it. Anything else (function calls,
  # variables, sigils, interpolation) is rejected *before* evaluation.
  #
  # Mix evaluates mix.lock as code. Parsing it as data means a hostile change to
  # the lockfile cannot run anything while the audit reads it.

  @spec parse(String.t()) :: {:ok, term()} | {:error, String.t()}
  def parse(source) when is_binary(source) do
    case Code.string_to_quoted(source) do
      {:ok, ast} ->
        if literal?(ast) do
          {value, _binding} = Code.eval_quoted(ast)
          {:ok, value}
        else
          {:error,
           "contains something other than plain data (function call, variable, sigil or interpolation)"}
        end

      {:error, error} ->
        {:error, "does not parse: #{inspect(error)}"}
    end
  end

  defp literal?(ast) when is_atom(ast) or is_number(ast) or is_binary(ast), do: true
  defp literal?(list) when is_list(list), do: Enum.all?(list, &literal?/1)
  defp literal?({a, b}), do: literal?(a) and literal?(b)
  defp literal?({:{}, _meta, args}) when is_list(args), do: literal?(args)
  defp literal?({:%{}, _meta, pairs}) when is_list(pairs), do: literal?(pairs)
  defp literal?(_other), do: false
end
