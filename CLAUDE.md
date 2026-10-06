# certpull

Before changing anything in this repository, read **[CONTEXT.md](CONTEXT.md)**.

It holds the design decisions together with the alternatives that were
rejected, the invariants that must not be broken, the bash traps specific to
this code, and a bug history with the real root causes (every one of them
looked like something other than what it was).

`README.md` describes **how** the system works and how to deploy it.
`CONTEXT.md` describes **why** it looks the way it does.

The short version:

- Every example in the code and the documentation uses `example.com`. Keep
  real customer names, hostnames and IP addresses out of this repository.
- Nothing lands in the agent's destination directory before the full set of
  verification steps has passed.
- The `hostid` in the forced command is written on the server side — a client
  cannot substitute it.
- Test with `certpull-verify` and stubs, never against production ACME.
- `set -Eeuo pipefail` everywhere: `(( x )) && cmd` kills the script when `x`
  is zero — use `if`. And a function called as `f || rc=1` has `set -e`
  disabled throughout its body, so catch failures explicitly.
