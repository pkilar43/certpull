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

### The private key is generated centrally (not from a CSR)

**A deliberate choice.** Simpler, and it matches the model of comparable
pull-based certificate managers. The price: the server is a single point of
compromise for every private key — treat it as a PKI host.

An option for later: a CSR mode in which the key never leaves the LAN machine.
`certpull-pull-shell` is prepared for it — add a `csr` verb to the whitelist
and feed it to `lego --csr` on the server side. It was not built because
nobody needed it yet.

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

8. **`process_host` is called as `process_host ... || rc=1`, which DISABLES
   `set -e` for the whole function body.** This is the standard bash trap: a
   function invoked in a conditional context does not abort on error. Every
   failure inside it has to be caught **explicitly** (`if ! cmd; then
   ... return 1; fi`), otherwise execution carries on and the final `return 0`
   reports success. That exact bug lived in the publishing step — see section 5.
   **When adding anything to `process_host`, check that failures are caught.**

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

The whole codebase can be exercised locally with stubs on `PATH` — substitute
`dig`, `nsupdate`, `knotc`, `lego`, `ssh`. That is how the following were
tested: certificate publishing, pulling through the forced command, rotation,
detection of a tampered bundle, rollback after a failed reload, choosing a
hostid from the list, refusing somebody else's hostid, the agent's
multi-profile mode, the preflight against four shapes of DNS response,
cleaning up stale TXT records, and detecting an open zone transaction.

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
* **CSR mode** — see section 2.
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
