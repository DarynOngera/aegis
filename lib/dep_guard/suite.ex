defmodule DepGuard.Suite do
  @moduledoc """
  Drop-in ExUnit suite. In the application under test:

      # test/security/dependencies_test.exs
      defmodule MyApp.DependencySecurityTest do
        use DepGuard.Suite
      end

  Options:

    * `:root` - project root holding `mix.lock` (default: current directory; for an
      umbrella, point at the umbrella root)
    * `:policy` - policy file relative to root (default `.dep_guard.exs`)
    * `:base_ref` - git ref to diff `mix.lock` against (default: env `DEP_GUARD_BASE_REF`;
      the lock-change test is only defined when set)
    * `:eef_feed` - cross-check the EEF CNA OSV feed (default `true`; set `false` to omit)
    * `:eef_osv_base` - override the feed base URL

  Offline tests always run. The audits that need the network are tagged `:online`:

      mix test test/security                    # everything
      mix test test/security --exclude online   # offline only
  """

  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      use ExUnit.Case, async: false

      @moduletag :dependency_security
      @dep_guard_opts opts
      base_ref =
        case Keyword.get(opts, :base_ref, System.get_env("DEP_GUARD_BASE_REF")) do
          "" -> nil
          ref -> ref
        end

      @dep_guard_base_ref base_ref

      setup_all do
        case DepGuard.Checks.context(@dep_guard_opts) do
          {:ok, ctx} -> {:ok, dep_guard: ctx}
          {:error, message} -> raise "dep_guard: #{message}"
        end
      end

      test "mix.lock is plain data with checksums, and git deps are pinned to commits", %{dep_guard: ctx} do
        DepGuard.Suite.assert_no_problems(DepGuard.Checks.lockfile(ctx))
      end

      test "dependencies only come from allowed sources", %{dep_guard: ctx} do
        DepGuard.Suite.assert_no_problems(DepGuard.Checks.sources(ctx))
      end

      test "policy waivers are complete, unexpired and still relevant", %{dep_guard: ctx} do
        DepGuard.Suite.assert_no_problems(DepGuard.Checks.policy_hygiene(ctx))
      end

      test "mix.exs does not bypass the policy with its own ignore lists" do
        DepGuard.Suite.assert_no_problems(DepGuard.Checks.project_ignores())
      end

      if @dep_guard_base_ref do
        test "mix.lock changes since #{@dep_guard_base_ref} are safe", %{dep_guard: ctx} do
          DepGuard.Suite.assert_no_problems(DepGuard.Checks.lock_changes(ctx, @dep_guard_base_ref))
        end
      end

      @tag :online
      @tag timeout: 300_000
      test "no retired or vulnerable packages (mix hex.audit)", %{dep_guard: ctx} do
        DepGuard.Suite.assert_no_problems(DepGuard.Checks.hex_audit(ctx))
      end

      @tag :online
      @tag timeout: 300_000
      test "no known advisories (mix deps.audit)", %{dep_guard: ctx} do
        DepGuard.Suite.assert_no_problems(DepGuard.Checks.mix_audit(ctx))
      end

      if Keyword.get(opts, :eef_feed, true) do
        @tag :online
        @tag timeout: 300_000
        test "no advisories in the EEF CNA feed", %{dep_guard: ctx} do
          feed_opts =
            case Keyword.fetch(@dep_guard_opts, :eef_osv_base) do
              {:ok, base} -> [base_url: base]
              :error -> []
            end

          DepGuard.Suite.assert_no_problems(DepGuard.Checks.eef_feed(ctx, feed_opts))
        end
      end
    end
  end

  @doc false
  def assert_no_problems([]), do: :ok

  def assert_no_problems(problems) when is_list(problems) do
    ExUnit.Assertions.flunk("#{length(problems)} problem(s):\n\n" <> Enum.map_join(problems, "\n\n", &("  * " <> &1)))
  end
end
