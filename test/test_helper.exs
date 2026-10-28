# Tests pass `--today` to pin waiver expiry; the CLI only accepts it with this opt-in.
System.put_env("DEP_GUARD_ALLOW_TODAY", "1")

ExUnit.start(exclude: [:online])
