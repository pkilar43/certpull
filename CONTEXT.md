# CONTEXT.md — for whoever (or whatever) picks this project up next

This file exists so that the code can be changed without access to the
conversation in which certpull was built. `README.md` describes **how** the
system works. This one describes **why** it looks the way it does, what must
not be broken, and which mines have already been stepped on.

---

## 1. The problem in one paragraph

A few dozen machines on a LAN need Let's Encrypt certificates. They have no
port 80/443 reachable from the internet, so HTTP-01 is out. We do not want to
hand them DNS-provider API tokens, and we do not want the PKI server to SSH
into the LAN. The solution: one internet-facing server performs all of DNS-01
on everyone's behalf, and the LAN machines **come and ask for the certificate
themselves** over SSH — the direction of the connection is reversed, so nothing
has to be opened at the network edge.

---

## 2. Design decisions and the alternatives that were rejected

Every one of these was a deliberate choice. If you want to reverse one, read
what justified it first.

### Pull instead of push — non-negotiable

This is the entire point of the project. The target machines have no public
address, so the server has no way in. The agent connects outward, fetches its
certificate and installs it locally. Any suggestion along the lines of "could
the server just scp it over" is by definition impossible in this environment.

### Two modes for the private key, chosen per host on the server

`CSR_MODE` in `hosts.d/<hostid>.conf` decides:

* **`full`** (the default, and the original behaviour) — the server generates
  the key and publishes it with the certificate. Simpler, one step to the first
  certificate, matches comparable pull-based managers. The price: the server is
  a single point of compromise for every private key in the fleet.
* **`csr`** — the agent generates its own key, it never leaves that machine,
  and only a CSR goes to the server, which publishes the certificate alone.

The reasoning that led to `csr`, and which is worth not re-deriving: a
certificate is **public data**. Its authenticity does not come from the channel
it arrived through — it comes from chaining to Let's Encrypt *and* matching a
private key that only ever existed on the machine using it. Those two local
checks are self-sufficient, so nothing in the middle has to be trusted. That is
also why `csr` mode needed no new transport, no encryption and no signatures:
the question "how do we protect the key in transit" dissolves once the key does
not travel.

Alternatives considered and **rejected** while designing it:

* **Encrypting the bundle (`age`, encrypt-to-host-key)** — solves confidentiality
  for a travelling key, but `age` does not sign, so it gives no authenticity on
  its own and would have needed a second mechanism
  (`ssh-keygen -Y sign`) beside it. In the CSR model there is nothing to
  encrypt, so both disappear. Worth revisiting **only** if `full` mode ever has
  to survive an untrusted channel.
* **Moving the transport to HTTPS** — orthogonal, and not done here. The real
  argument for it is environmental, not cryptographic: outbound port 22 is
  blocked on many corporate and hospital LANs where an explicit HTTP proxy on
  443 is the only way out. If that day comes, the thing to do is extract the
  transport (the bundle format becomes the contract, SSH and HTTPS become two
  ways to move it) rather than grow a second trust model. The invariant to keep
  is the one below: the client must not be able to name the resource it fetches.
* **`submit` triggering issuance synchronously** — tempting for the first
  certificate, but it hands a client the ability to make the server start ACME
  orders on demand, which is a rate-limit denial of service. The CSR is stored
  and the next scheduled run (or a manual `certpull-issue <hostid>`) picks it
  up.
* **Automatic key rotation on every renewal** — rejected. Renewal keeping the
  existing key is what a 45-day certificate wants; rotation is an explicit
  `certpull-agent --rotate-key`. The pending-key machinery exists anyway,
  because the first key of a new host is in exactly that state.

### Knot DNS + lego (not acme-dns, not BIND + certbot)

**A deliberate choice.** The key observation: **acme-dns exists so that many
hosts can publish their own challenges.** Here, ACME is performed exclusively
by the central server, so acme-dns's entire HTTP API and sqlite layer is
redundant — a local zone accepting `nsupdate` with TSIG plus
`lego --dns rfc2136` is enough. Fewer moving parts.

### One delegated zone serves every domain

**The CNAME target does not have to live in the same domain as the name being
validated.** This is the crux, and the thing most often misunderstood.
`_acme-challenge.host.client-a.com` can point at
`host.client-a.com.acme.example.com`. One zone, one TSIG key, one A record.

`certpull-zone` allows further zones to be added, but that is for the case "I
want this client's delegation to originate from the client's own domain", not a
technical necessity. Do not run `install-server.sh` a second time — it guards
against that itself, but it was never meant for it.

### CNAME records are set once and never touched

The only thing that changes during validation is an ephemeral TXT record in a
zone we fully control. No automation on the client zones' side at all.

---

## 3. Invariants — do not break these without a very good reason

1. **Nothing lands in the agent's destination directory before the full set of
   checks has passed.** The order: `SHA256SUMS` → fingerprint vs `meta.json` →
   public key from the certificate equal to the one derived from the private
   key → `checkend 86400` → `checkhost` for every name → and only then
   `install` to `.new.*` and `mv` (atomically). A rejected bundle leaves no
   trace. There is a test for this.

2. **The `hostid` in the forced command is written on the server side.** The
   client controls only `SSH_ORIGINAL_COMMAND`, from which we take the first
   two words and validate them against the verb whitelist and against the
   hostid list assigned to that key. Never trust a `hostid` sent by the client
   without checking that it belongs to the list.

3. **The `certpull` account must have a real shell** (`/bin/bash`), not
   `nologin`. sshd runs the forced command through the login shell. Security
   comes from `restrict` + `command=`, not from the shell.

4. **`RELOAD_CMD` returns an error → roll back to the previous certificate.**
   The copy lives in `$DEST/.previous`.

5. **The agent never removes anything from the destination directory that it
   did not write itself.** After a `FILE_STYLE` change the old files stay —
   deliberately.

6. **Secrets never reach `argv`.** TSIG is passed as `nsupdate -k <file>`,
   never `-y hmac:...:secret` — the latter would be visible in `ps`.

7. **A failure on one host does not abort the run.** `certpull-issue` walks
   every host independently; one missing CNAME must not block the renewal of
   all the others. The exit code is 1 if **any** host failed, plus a
   `summary: N OK, M failed -> <list>` line in the log.
   **But mind the consequence** — see the next point.

8. **`process_host` is called as `process_host ... || rc=$?`, which DISABLES
   `set -e` for the whole function body.** This is the standard bash trap: a
   function invoked in a conditional context does not abort on error. Every
   failure inside it has to be caught **explicitly** (`if ! cmd; then
   ... return 1; fi`), otherwise execution carries on and the final `return 0`
   reports success. That exact bug lived in the publishing step — see section 5.
   **When adding anything to `process_host`, check that failures are caught.**
   It returns three values now: 0 done, 1 failed, 2 waiting for a CSR.

9. **In CSR mode, the set of names in the CSR must EXACTLY equal the host's
   `DOMAINS`** — not a subset, not a superset. This is the whole security
   boundary of that mode, because `lego --csr` takes the names to validate from
   the CSR and refuses `--domains` altogether. If a client could put arbitrary
   names in its CSR it could obtain a certificate for somebody else's domain.
   The check lives in **one** place, `server/certpull-csrlib.sh`, and runs
   twice: in `certpull-pull-shell` at submit time (so the agent gets a usable
   error) and again in `certpull-issue` before the CA is called (because it does
   not trust a file on disk, and `DOMAINS` may have changed meanwhile). Never
   add a second implementation of it.

10. **A pending private key is promoted to active only once a certificate
    matching it has been installed.** Promoting earlier would leave the service
    holding a key and a certificate that do not belong together. The key is
    moved into place immediately before the certificate files, both as renames
    inside one directory, and `RELOAD_CMD` runs only after all of them.

11. **In CSR mode the mode and the domains come from the `config` verb, never
    from `meta.json`.** `meta.json` describes the **last publication**, so right
    after a host is switched between modes it still describes the old one. An
    agent that believed it would keep running in the previous mode until the
    next renewal. `config` reads the host file, which is the authority. For the
    same reason `certpull-issue` compares the published mode **and** the
    published domain list against the configuration and forces a re-issue when
    either changed — otherwise a still-valid certificate means nothing happens
    at all.

12. **In CSR mode nothing that looks like a private key is ever published or
    accepted.** The server publishes no `privkey.pem` and deletes the leftover
    one from `lego`'s store when a host moves into the mode; the agent refuses a
    bundle that contains one, and refuses a certificate that does not match its
    local key.

---

## 4. Code conventions and bash traps

All scripts: `set -Eeuo pipefail`, and clean under shellcheck at the `warning`
level. A few things to watch out for in that mode:

* **`(( x )) && cmd` kills the script under `set -e`** when `x` is zero — the
  whole list returns 1. Use `if (( x )); then cmd; fi`. The same applies to
  `[[ ... ]] && cmd` as a standalone statement. We tripped over this more than
  once.
* **A function invoked in a conditional context (`f || rc=1`, `if f`) has
  `set -e` disabled throughout its body.** This is the other side of the same
  coin and it is the more dangerous one: instead of killing the script, it
  silently carries on past an error. It applies to `process_host` and
  `preflight_domain` — see invariant 8.
* **Configuration files are `source`d in a loop.** Reset every variable the
  file might set before each `source`, and restore the global afterwards. The
  pattern: `GLOBAL_X="$X"` at the start, `X=""` before the source,
  `X="${X:-$GLOBAL_X}"` after. Otherwise one host's setting leaks into the next.
* **Do not parse `knotc` output by field position** — it prefixes every line
  with a `[zone.]` marker. Anchor on the record type instead (see `soa-min`).
* **Never split a domain list by leaving it unquoted.** `for d in $DOMAINS`
  undergoes **pathname expansion**, and these scripts run with
  `shopt -s nullglob` (they need it for the `hosts.d/*.conf` glob). A wildcard
  domain such as `*.lan.example.com` matches no file and is therefore **deleted
  from the list** — silently. Use `read -r -a arr <<<"$DOMAINS"` and iterate
  `"${arr[@]}"`. This had broken every wildcard host; see section 5.
* **`openssl x509 -checkhost` does not treat `example.com` as covered by
  `*.example.com`** — because it genuinely is not. Probe a wildcard with a
  label underneath it instead of stripping the `*.` prefix.
* **Do not regenerate files from tool output**, edit them in place.

### Adding a new configuration option

Put it in the template (`certpull.conf.example` / `agent.conf*.example`) **and**
decide which group it belongs to in `install-{server,agent}.sh`:

* `SAFE_SEED` / `AGENT_SAFE_SEED` — the template value is a sensible default
  for every installation. `--update` will append it to live configs
  automatically.
* everything else — deployment-specific (the NS name, the zone, the e-mail
  address, `HOSTID`, `DEST`). `--update` only reports that it is missing;
  nobody can guess the value.

The template value **must** be identical to the built-in default in the script
(`: "${X:=...}"` or `${X:-...}`), otherwise seeding it would change the
behaviour of a running installation.

### Keep the installer's sed patterns in sync with the templates

`install-server.sh` generates `knot.conf` and the zone file by running `sed`
over `knot.conf.example` and `acme-zone.example`, substituting
`acme.example.com`, `ns-certpull.example.com`, `pki.example.com` and
`REPLACE_ME_WITH_KEYMGR_OUTPUT`. If a template is edited to use a different
domain without updating those patterns, **sed silently matches nothing** and
the generated files keep the template's domain instead of the arguments passed
to the installer. This has already happened once. There is no automatic guard,
so check it whenever you touch a template.

### How to test without touching Let's Encrypt

```bash
./tests/run-tests.sh
T=/var/tmp/cp-test T_KEEP=1 ./tests/run-tests.sh      # keep the sandbox to poke at
CERTPULL_OLD_REF=<git-ref> ./tests/run-tests.sh       # also run a pre-CSR agent
```

It builds a throwaway sandbox with stubs for `lego`, `dig`, `nsupdate`, `knotc`
and `ssh`, and never contacts an ACME server or a real zone. The `ssh` stub is
the interesting one: it does what sshd does — puts the client's string into
`SSH_ORIGINAL_COMMAND`, passes stdin through, and runs
`certpull-pull-shell` with a hostid allowlist — so the forced command, the verb
whitelist and `submit` are exercised for real rather than mocked.

The `lego` stub mirrors the parts of the real interface this code depends on,
including the ones that would otherwise only fail in production: `--csr`
together with `--domains` is fatal, `--csr` writes **no** `.key`, and the output
file name comes from the CSR's Subject CN (falling back to the first DNS SAN),
with `*` sanitised to `_`. Those facts were read out of lego's `cmd/flags.go`,
`cmd/certs_storage.go` and `certcrypto/crypto.go` — `--csr`/`-c` is a **global**
flag, so it belongs before the subcommand.

The suite covers both modes end to end, the CSR bootstrap, renewal, rotation,
mode switches in both directions, wildcard and pure-wildcard hosts, `DOMAINS`
changes, every authorisation refusal (extra/missing/foreign SAN, a foreign
hostid, a weak key, a full-mode host), a compromised server pushing a
certificate for a foreign key, a tampered bundle with consistent checksums, and
compatibility with an older agent and an older server. Five real bugs in this
feature were found by it before any of it ran on a real machine — keep adding
to it rather than testing by hand.

On a live installation: `certpull-verify` performs the full round trip (writes
a test TXT, queries public resolvers, deletes it) **without a single request to
Let's Encrypt**. Use that instead of burning rate limits.

When translating or refactoring a script, compare the "code skeleton" of the
old and new versions — strip comments and the contents of string literals, then
diff. If the skeletons match, only comments and messages changed, not the
logic.

---

## 5. Bug history and the real root causes

This is the most valuable part of this file. Every one of these symptoms looked
like something other than what it actually was.

| Symptom | The real cause |
|---|---|
| `rfc2136: failed to insert: ... code=REFUSED`, with `fqdn=_acme-challenge.<domain>` | lego **did not follow the CNAME** and tried to update the original name. How to spot it: the `fqdn=` in the error is the production name, not the one in the delegated zone. Causes: no CNAME, or `/etc/resolv.conf` pointing at 127.0.0.1 (Knot is authoritative, not recursive → REFUSED → lego concludes there is no CNAME). Fix: pass `DNS_RESOLVERS` explicitly as `--dns.resolvers`. |
| `This account is currently not available.` on `ssh certpull@...` | The key **was accepted** — that message comes from `nologin`. sshd runs the forced command through the login shell. `usermod -s /bin/bash certpull`. |
| Preflight reporting `Knot answered NXDOMAIN` on a perfectly good delegation | Our own bug: it checked `status == NOERROR`. The CNAME target practically never exists (the TXT lives for a few dozen seconds), so `NXDOMAIN` **with the `aa` flag** is the correct result. Authoritativeness is decided by **the `aa` flag, not the status**. |
| lego: "propagation OK", Let's Encrypt: `No TXT record found` | lego asks the **authoritative server directly** by default (that is our own Knot, which always answers "it is there"), while LE resolves **recursively** from several perspectives (MPIC). lego's green result proved nothing. Hence `--dns.propagation-rns` and `certpull-verify`. |
| `certpull-verify`: the CNAME target answers `NOERROR` instead of `NXDOMAIN` | **A stale TXT record from an interrupted run.** lego issues `update add`, not `replace`; after a Ctrl-C the cleanup never runs. The new token is added next to the old one, and resolvers holding the old RRset keep serving it for its full TTL — so LE sees a set without its own token. Hence `PURGE_STALE_TXT`. |
| `DNS update failed: ... 127.0.0.1:53: i/o timeout` while Knot is running fine | **An open zone transaction.** `knotc zone-begin` blocks dynamic updates, and Knot does not refuse them — it simply stops answering. Left behind by an interrupted `zone-begin`. `knotc zone-abort <zone>`. Now detected by the preflight and by `certpull-verify`. |
| `soa-min`: `invalid arithmetic operator (error token is ".example.com.")` | Our own bug: `knotc zone-read` prefixes its lines with `[zone.]`, so counting fields from the start is off by one and the e-mail address from the SOA lands where the serial was expected. |
| `certpull-issue` exiting 0 while the certificate never reached the `pull` directory | Our own bug: `publish` returned 1, but nothing checked its result — the following `return 0` reported success (because `set -e` is disabled in a function called via `\|\| rc=1`). Effect: the timer saw success, nobody was alerted, and the agents never received the certificate. **A silent failure, found only because somebody asked the right question.** |
| `install-server.sh` writing the template's domain into `knot.conf` instead of the one passed as an argument | Our own bug: the templates were edited to a different domain while the `sed` patterns in the installer still looked for `example.com`, so the substitution silently matched nothing. See section 4. |
| A wildcard host getting a certificate covering fewer names than configured, or `lego` refusing to run at all with "Please specify --domains" | Our own bug, and it predated CSR mode: `for d in $DOMAINS` is subject to **pathname expansion**, and the scripts run with `shopt -s nullglob`, so `*.lan.example.com` matched no file and vanished from the list. A mixed list quietly lost its wildcard; a pure-wildcard host had no `--domains` left at all. Fixed by `read -r -a` everywhere (`certpull-issue`, `certpull-host cname`, `certpull-verify`, the agent's CSR builder and its `checkhost` loop). |
| A host switched to `CSR_MODE="yes"` carrying on exactly as before, private key still published | Our own bug: no renewal was due and the fingerprint had not changed, so nothing was re-issued and nothing was re-published. The published **mode** and the published **domain list** are now part of the re-issue decision. The same hole made adding a name to `DOMAINS` a no-op until the natural renewal weeks later. |
| An agent in a loop: a new key generated on every run, a CSR sent for it, and the certificate signed for the previous one never accepted | Our own bug: the "switched from full to csr, generate a fresh key" condition stayed true until a matching certificate was *installed*, so each run threw away the pending key the server was in the middle of signing. Fixed by never generating a second pending key while one exists (`--rotate-key` is the deliberate exception). |
| An agent happily serving a certificate that no longer covered the configured names after `DOMAINS` changed on the server | Nothing locally revealed it: key and certificate were a perfectly matching pair, just for the wrong name set. The server now reports `csr_state=ok\|stale\|missing` through the `config` verb, using the same `csr_check` that guards `submit`, and the agent resubmits on `stale`. |

**The methodological takeaway:** with DNS-01, almost every symptom has a cause
one level deeper than the message suggests. Before you start guessing,
reproduce what the CA actually does — `certpull-verify` exists for exactly
that.

---

## 6. Things not to do

* **Do not run `install-server.sh` a second time** for another domain — that is
  what `certpull-zone add` is for.
* **Do not test against production ACME.** The Let's Encrypt limit is 5
  identical sets of names per week. For testing: staging, or `certpull-verify`.
* **Do not set `LEGO_DISABLE_CNAME_SUPPORT`** — the entire delegation rests on
  CNAME following.
* **Do not put `127.0.0.1` in `DNS_RESOLVERS`.**
* **Do not add `NoNewPrivileges=yes`** to `certpull-agent@.service` while
  `RELOAD_CMD` uses `sudo` — sudo needs setuid.
* **Do not let a client choose what it asks for.** The `hostid` comes from the
  forced command and the names come from `DOMAINS`; a client only ever supplies
  a verb and a hostid that must already be on its list. Any new verb has to
  keep that property — and a new verb that takes a *parameter* needs a very
  good reason.
* **Do not duplicate the CSR name check.** One implementation, in
  `certpull-csrlib.sh`, sourced by both sides.
* **Do not commit live configuration, keys, zone files or the `lego` store.**
  `.gitignore` blocks all of it, including the case where somebody runs the
  installer from inside a clone. Note the matching rule that caused a real hole
  once: a pattern containing `/` is anchored to the directory holding
  `.gitignore`, so `hosts.d/*.conf` does **not** match
  `server/hosts.d/foo.conf` — hence the `**/` prefix.

---

## 7. What is next

* **`dns-persist-01`** — as of August 2026 it is **not in Let's Encrypt
  production**. Announced in February 2026 (staging Q1, production Q2), but in
  June 2026 LE stated it would not deploy until an issue with client-computed
  data in the record was resolved; the draft is awaiting a `-02` update. When
  it does land, the migration is: one `_validation-persist` record per domain
  instead of the CNAMEs, one lego switch changed, and Knot plus the NS
  delegation can be dropped. **The SSH pull model stays unchanged** — it is
  orthogonal to the challenge type. Worth watching `dns-account-01` too; it
  tends to ship earlier.
* **45-day Let's Encrypt certificates** — hence `RENEW_DAYS=15` (about one
  third of the lifetime). If the lifetime shortens further, scale that down
  proportionally.
* **An HTTPS transport** — see section 2 for why it is not here and what the
  motivation would be (outbound 22 blocked, 443 through a proxy being the only
  way out). Extract the transport first; do not grow a second trust model.
* **Making `csr` the default** — plausible once enough of the fleet runs an
  agent that knows `submit`. It is not the default today purely for
  compatibility: an older agent fails closed against a CSR-mode host, which is
  safe but is still a failure.
* **Notifications** — `NOTIFY_CMD` is wired up on both sides, but nobody has
  written an implementation yet.

---

## 8. Style this code was written in

* Every error message should say **what to do**, not just what happened. See
  `certpull-verify` and the preflight: they print the exact record to paste or
  the exact command to run.
* Prefer one tool that reproduces the real failure over several that guess at
  it.
* Comments explain **why**, not what the line does. A comment that only
  restates the code is noise; a comment recording the reason a non-obvious
  choice was made is the most valuable thing in the file.
