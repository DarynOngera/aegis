defmodule DepGuard.Runner do
  @moduledoc false
  # Runs a mix task in a fresh OS process in the project root.
  #
  # A subprocess is used on purpose: `mix hex.audit` must run before anything that
  # loads or starts the application, which a test process has already done.

  @type result ::
          {:ok, String.t()}
          | {:failed, non_neg_integer(), String.t()}
          | {:missing_task, String.t()}
          | {:error, String.t()}

  @spec mix([String.t()], keyword()) :: result()
  def mix(args, opts) do
    root = Keyword.fetch!(opts, :root)

    case System.find_executable("mix") do
      nil ->
        {:error, "`mix` was not found on PATH"}

      mix ->
        env = [{"MIX_ENV", to_string(Keyword.get(opts, :mix_env, :test))} | Keyword.get(opts, :env, [])]

        {output, status} = System.cmd(mix, args, cd: root, env: env, stderr_to_stdout: true)

        cond do
          status == 0 -> {:ok, output}
          String.contains?(output, "could not be found") -> {:missing_task, output}
          true -> {:failed, status, output}
        end
    end
  end
end
