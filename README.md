# certpull

Issue Let's Encrypt certificates centrally on one internet-facing server and
let LAN machines **pull them over SSH** — machines that are not reachable from
the internet at all.

Nothing listens on the LAN side. All traffic goes **LAN → internet**, so
nothing has to be forwarded through NAT or opened on the edge firewall.

> Changing this code? Start with **[CONTEXT.md](CONTEXT.md)** — design
> decisions, invariants, and a bug history with the real root causes.

---

## Why it is built this way

| Problem | How certpull solves it |
|---|---|
| LAN hosts have no port 80/443 from the internet, so HTTP-01 is out | DNS-01, performed exclusively on the central server |
| We do not want DNS-provider API tokens on 40 hosts | `_acme-challenge` is CNAME'd into our own zone; the TSIG key never leaves the server |
| We do not want the PKI server to SSH into the LAN | Reversed direction: the agent in the LAN connects out and pulls its own certificate |
| An agent key may leak | `restrict` + forced command, a whitelist of verbs, and each key sees only its own `hostid` |
| A tampered or corrupt transfer | `SHA256SUMS`, key/certificate match, `checkend`, `checkhost`, and rollback if the reload fails |

---

## Architecture

```
                     Let's Encrypt
                          │  DNS-01: TXT _acme-challenge.app.example.com
                          │            └─ CNAME ──► app.example.com.acme.example.com
                          ▼
   ┌──────────────────────────────────────────────────┐
   │  public server  (certpull server)                │
   │                                                  │
   │   Knot DNS  ── authoritative for acme.example.com│
   │      ▲  nsupdate/TSIG (127.0.0.1)                │
   │      │                                           │
   │   lego (rfc2136)  ◄── certpull-issue  ◄── timer  │
   │      │                                           │
   │      ▼                                           │
   │   /var/lib/certpull/pull/<hostid>/               │
   │      cert.pem chain.pem fullchain.pem            │
   │      privkey.pem meta.json SHA256SUMS            │
   │      ▲                                           │
   │   sshd → forced command: certpull-pull-shell     │
   └──────┼───────────────────────────────────────────┘
          │  SSH (outbound from the LAN, port 22)
   ┌──────┼───────────────────────────────────────────┐
   │  LAN │  (no inbound access from the internet)    │
   │      │                                           │
   │  certpull-agent  ── hourly timer                 │
   │      1. `meta`  → compare the fingerprint        │
   │      2. `fetch` → tar, then verify               │
   │      3. atomic install + service reload          │
   └──────────────────────────────────────────────────┘
```

The key property: **the CNAME records in the production zones are set once and
never touched again.** The only thing that changes during validation is an
ephemeral TXT record in the `acme.example.com` zone, which the certpull server
controls entirely.

---

## Quick start

### 1. The server

A 1 GB / 1 vCPU VM is plenty (Knot + lego use a few MB of RAM). Debian 13.
Give it a static or reserved IP — otherwise rebuilding the machine means
changing the A record in the parent zone.

```bash
git clone <repo> /opt/certpull && cd /opt/certpull/server
./install-server.sh acme.example.com ns-certpull.example.com pki@example.com
```

The installer handles: packages, lego, the `certpull` user, directories, the
TSIG key, Knot with the zone, `sshd_config.d/50-certpull.conf`, the timer and
ufw (22/53).

### 2. DNS delegation (once, at your DNS operator)

```
ns-certpull.example.com.   3600  IN  A     <server IPv4>
ns-certpull.example.com.   3600  IN  AAAA  <server IPv6>
acme.example.com.          3600  IN  NS    ns-certpull.example.com.
```

No glue is needed — the NS name lives in the parent zone, not in the delegated
one.

Also recommended, to limit which CAs may issue for your domains:

```
example.com.  IN  CAA  0 issue "letsencrypt.org"
```

Verify:

```bash
dig +trace SOA acme.example.com
dig @<server IP> SOA acme.example.com
```

### 3. A host

On the server:

```bash
certpull-host add srv-web-01 app.example.com www.app.example.com
```

It prints the records to paste into the production zone:

```
_acme-challenge.app.example.com.      300 IN CNAME app.example.com.acme.example.com.
_acme-challenge.www.app.example.com.  300 IN CNAME www.app.example.com.acme.example.com.
```

On the LAN machine:

```bash
cd /opt/certpull/agent
./install-agent.sh srv-web-01
```

The server address is optional — it defaults to
`certpull@ns-certpull.example.com`. Deliberately `ns-certpull` rather than a
separate name: that one **must** exist, because the NS delegation of the
`acme` zone points at it, so it always resolves and always points at the right
machine. Pass a second argument when the server lives elsewhere
(`./install-agent.sh srv-web-01 certpull@other-host`), or set
`CERTPULL_DEFAULT_SERVER` to change the default permanently.

> One LAN host can pull several certificates — see
> [How many DNS records](#how-many-dns-records) and
> [Several certificates for one agent](#several-certificates-for-one-agent).

The script prints a ready-to-run `certpull-host key …` command — run it on the
server. **Compare the host-key fingerprint** it shows with the one on the
server (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`);
`StrictHostKeyChecking=yes` is enabled permanently.

### 4. First issuance

Staging first (it has no rate limits):

```bash
sed -i 's|acme-v02|acme-staging-v02|' /etc/certpull/certpull.conf
certpull-issue srv-web-01
```

Once that works, switch back to production and delete the staging account:

```bash
sed -i 's|acme-staging-v02|acme-v02|' /etc/certpull/certpull.conf
rm -rf /var/lib/certpull/lego/accounts
certpull-issue --force srv-web-01
```

On the LAN host:

```bash
certpull-agent --check
certpull-agent
```

---

## Updating after changes in the repository

```bash
git pull
cd server && ./install-server.sh --update      # the certpull server
cd agent  && ./install-agent.sh  --update      # a LAN host (root mode)
             ./install-agent.sh  --update --user certpull
```

This replaces **only the scripts and the systemd units**. It does not touch
`certpull.conf`, `knot.conf`, the zones, sshd, ufw, the `certpull` account, SSH
keys, `known_hosts` or the state of the timers. Every script is run through
`bash -n` before installation — a syntax error aborts the update instead of
putting a broken file in place.

The most useful part is **detecting new configuration keys**. After an update
that introduces a new option you get:

```
==> configuration
   seeding the missing keys (values = defaults, behaviour unchanged):
     DNS_RESOLVERS="8.8.8.8:53,9.9.9.9:53"
     PROPAGATION_RNS="yes"
     PURGE_STALE_TXT="yes"
   NOTE: these keys depend on the deployment -- set them BY HAND in /etc/certpull/certpull.conf:
     ACME_NS_NAME="ns-certpull.example.com"
```

The distinction is deliberate: keys with a universally sensible default are
appended automatically (with a backup of the config, and with identical
behaviour, because the scripts already used those values as built-in
defaults), while keys that depend on the particular deployment — the NS name,
the zone, the e-mail address — are only reported. The script will not guess
them for you.

`--dry-run` shows everything without writing anything. Running it again is
safe: `systemd units unchanged`, `has every key`.

---

## Day-to-day operation

```bash
certpull-status                 # overview: days to expiry, publication date
certpull-host list
certpull-issue                  # the same thing the timer does
certpull-issue --dry-run
certpull-issue --force srv-web-01
certpull-issue --preflight      # delegation check only, without asking LE
journalctl -u certpull-renew -n 50
journalctl -t certpull-pull     # who pulled what, and when
```

On a LAN host:

```bash
certpull-agent --check
systemctl list-timers certpull-agent.timer
journalctl -u certpull-agent -n 50
```

**Hosts are independent of each other.** One missing CNAME or one failed
renewal does not abort the run — `certpull-issue` walks every host and only
summarises at the end:

```
summary: 38 OK, 2 failed -> srv-mail-02 srv-legacy-07
```

The exit code is 1 if **any** host failed, so `systemctl status
certpull-renew` reports the failure, and `NOTIFY_CMD` (when configured) is
called once per broken host. The same holds on the agent side: in
multi-profile mode each profile is a separate process with its own lock, so
one failure does not block the others.

---

## Several domains on one installation

**Do not run `install-server.sh` a second time for another domain.** The
installer detects that Knot is already configured and skips that part, but it
was never meant for this.

In most cases **nothing needs to be added**: a single `acme.example.com` zone
serves any number of domains, because **the CNAME target does not have to live
in the same domain as the name being validated**:

```
_acme-challenge.app.example.com.        CNAME  app.example.com.acme.example.com.
_acme-challenge.smtp-relay.example.com. CNAME  smtp-relay.example.com.acme.example.com.
_acme-challenge.portal.<other-domain>.  CNAME  portal.<other-domain>.acme.example.com.
```

The third line is the whole point: the validated name lives in a completely
different domain and still points into our single zone.

One zone, one TSIG key, one A record. That is the default and recommended
path — exactly the mechanism acme-dns is built on.

### When a separate zone does make sense

There are two good reasons: you want each client's delegation to originate
from **that client's own domain** (no external dependency on `example.com`,
and the client sees the record in its own zone), or a client is moving its
domain to another operator and does not want to leave behind a CNAME pointing
at somebody else's infrastructure.

In that case you add a zone, not an installation:

```bash
certpull-zone add acme.<other-domain>     # creates the zone file, appends to knot.conf, knotc reload
certpull-zone list
certpull-zone show acme.<other-domain>    # delegation records to paste
certpull-zone del acme.<other-domain>     # detaches it; the zone file stays on disk
```

The `A`/`AAAA` record for `ns-certpull.example.com` exists **once** — the
delegation from every further domain points at that same name:

```
acme.<other-domain>.  3600  IN  NS  ns-certpull.example.com.
acme.<third-domain>.  3600  IN  NS  ns-certpull.example.com.
```

A host is bound to a zone when you add it (or via the `ACME_ZONE` field in
`/etc/certpull/hosts.d/<hostid>.conf`; empty = the default zone):

```bash
certpull-host add --zone acme.<other-domain> srv-xx-01 portal.<other-domain>
```

`certpull-zone` backs up `knot.conf` before every change and runs
`knotc conf-check` **before** reloading — a bad entry cannot take down the
zones that already work.

### What about a second installation?

A separate machine only makes sense if you want to isolate clients' private
keys from one another (compromising one machine then exposes only one client's
keys), or you have a contractual requirement about data location. That means a
full second installation: its own machine, its own TSIG key, its own ACME
account, its own `ns-certpull.<domain>`. Two installations on **one** machine
(two Knots, two `pull` directories) leads nowhere — there is only one port 53.

---

## How many DNS records

**One CNAME per unique DNS name, not per certificate.** You set it once and
never touch it again — it does not change on renewal, on a key change, or when
switching CA.

The rules that make this tractable:

* **Per name, not per certificate.** A certificate for `app.example.com` +
  `www.app.example.com` needs two records, because Let's Encrypt validates
  each SAN separately.
* **The same name in two certificates still needs only one record.** Several
  TXT records can coexist under `_acme-challenge.<name>`, and `certpull-issue`
  serialises issuance anyway (`flock` plus one host at a time).
* **Wildcards are cheap.** `*.example.com` and `example.com` both validate
  under the **same** `_acme-challenge.example.com` — one record covers both.
* **Subdomains do not inherit.** `_acme-challenge.example.com` will not serve
  `app.example.com`; that one needs its own entry.

In practice: ~40 hosts with 1–2 names each is 40–80 CNAME entries, pasted once
during migration. `certpull-host add` prints them ready to copy, and
`certpull-host cname <hostid>` prints them again at any time.

If 80 entries is too much work, there are two ways out:

1. **A single wildcard certificate** `*.example.com` + `example.com` — exactly
   one CNAME record and one `hostid`, handed out to every host. The price is a
   shared private key for the whole LAN: compromising one machine compromises
   the certificate of all of them. Reasonable for internal services, wrong for
   hosts at different trust levels.
2. **An NS delegation instead of CNAMEs** for a whole branch, e.g.
   `intra.example.com. NS ns-certpull.example.com.` — then the certpull server
   is authoritative for that entire subtree and no `_acme-challenge` inside it
   needs an entry. It does require those names to genuinely live on the
   certpull server, so it only fits a dedicated internal zone.

A DNS wildcard (`*.example.com CNAME ...`) **will not work** as a shortcut:
once `app.example.com` exists as a node, `_acme-challenge.app.example.com`
stops matching the wildcard one level up.

---

## Several certificates for one agent

An `authorized_keys` entry takes a **list** of `hostid`s — the key has access
to all of them and to nothing else:

```
restrict,command="/usr/local/lib/certpull/certpull-pull-shell srv-web-01 srv-web-01-mail wildcard-lan" ssh-ed25519 AAAA... certpull-srv-web-01
```

Do not edit the file by hand — `certpull-host key` with the same key
**overwrites the list** of an existing entry:

```bash
certpull-host add srv-web-01-mail mail.example.com
certpull-host key srv-web-01,srv-web-01-mail "$(cat /tmp/srv-web-01.pub)"
#  -> updated an existing key: [srv-web-01] -> [srv-web-01 srv-web-01-mail]

certpull-host keys      # who has access to what
certpull-host del srv-web-01-mail   # drops the hostid from the list; the line goes only when the list is empty
```

The client picks a certificate with the second word of the command
(`fetch srv-web-01-mail`). Omitting it yields the first `hostid` on the list,
which keeps older agent configurations working unchanged. A request outside
the list is refused:

```
certpull: this key has no access to srv-off (allowed: srv-web-01 srv-web-01-mail)
```

The `list` verb tells an agent what it is entitled to:

```bash
certpull-agent --remote-list
```

---

## The agent as a dedicated user

The agent detects the mode from its UID — there is no separate switch:

| | root | dedicated user |
|---|---|---|
| config | `/etc/certpull/agent.conf` | `~/.config/certpull/agent.conf` |
| profiles | `/etc/certpull/agent.d/*.conf` | `~/.config/certpull/agent.d/*.conf` |
| SSH key | `/etc/certpull/id_ed25519` | `~/.ssh/id_ed25519` |
| known_hosts | `/etc/certpull/known_hosts` | `~/.ssh/known_hosts` |
| certificates | `/etc/ssl/certpull` (0755) | `~/certificates` (0700) |
| lock | `/run/lock` | `$XDG_RUNTIME_DIR` or `~/.cache/certpull` |
| file ownership | from `CERT_OWNER`/`KEY_OWNER` | the current user (`chown` is skipped) |

Every one of those values can be overridden in the configuration file.

```bash
./install-agent.sh --user certpull srv-web-01
./install-agent.sh --user certpull --reload-unit nginx srv-web-01
```

The installer creates a system account, `~/.ssh`, `~/certificates`, generates
the key, pins the server's host key and enables
`certpull-agent@certpull.timer`.

### File names

`FILE_STYLE` decides how the files in the destination directory are named:

| `FILE_STYLE` | files |
|---|---|
| `pem` (default) | `cert.pem` `chain.pem` `fullchain.pem` `privkey.pem` |
| `crtkey` | `<hostid>.crt` (full chain) `<hostid>.key` `<hostid>.chain.crt` `<hostid>.leaf.crt` |

In the service configuration you point at `<hostid>.crt` + `<hostid>.key`.
Changing `FILE_STYLE` does not delete files in the old format — the agent never
removes anything from the destination directory that it did not write itself;
clean up by hand.

The key and the certificate reach the directory **only after the full set of
checks has passed** (`SHA256SUMS`, fingerprint vs `meta.json`, key/certificate
match, `checkend`, `checkhost`), and then via `install` to a `.new.*` file plus
`mv`, so the replacement is atomic. A rejected bundle leaves no trace in the
directory at all.

### Reloading a service without root

`RELOAD_CMD` runs as that user, so it needs narrowly scoped passwordless
`sudo`. `--reload-unit` sets that up for you:

```
# /etc/sudoers.d/certpull-agent-certpull
certpull ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx
```

```
RELOAD_CMD="sudo -n /usr/bin/systemctl reload nginx"
```

That is also why the `certpull-agent@.service` unit does **not** set
`NoNewPrivileges=yes` — `sudo` needs setuid and would fail under it. If your
`RELOAD_CMD` is empty or does not use sudo, add a drop-in:

```bash
systemctl edit certpull-agent@certpull    # [Service] / NoNewPrivileges=yes
```

An alternative with no sudo at all: leave `RELOAD_CMD` empty and hook the
reload to a systemd `path` unit watching `~/certificates`.

### On the agent side

Each certificate has its own destination directory and its own reload command,
so instead of a single `/etc/certpull/agent.conf` you use a directory of
profiles:

```
/etc/certpull/agent.d/web.conf      HOSTID=srv-web-01        DEST=/etc/ssl/certpull/web   RELOAD_CMD="…apache2"
/etc/certpull/agent.d/mail.conf     HOSTID=srv-web-01-mail   DEST=/etc/ssl/certpull/mail  RELOAD_CMD="…postfix; …dovecot"
```

As soon as `agent.d/` contains any `*.conf`, the agent ignores `agent.conf` and
walks every profile — each with its own lock, so one failure does not block the
rest. Ready-made examples live in `agent/agent.d.example/`. The SSH key,
`known_hosts` and `SERVER` are the same in every profile.

---

## The pull protocol

An agent's key in `authorized_keys` on the server:

```
restrict,command="/usr/local/lib/certpull/certpull-pull-shell srv-web-01" ssh-ed25519 AAAA... certpull-srv-web-01
```

`restrict` disables pty, agent forwarding, port forwarding, X11 and tunnels.
The `hostid` is **written on the server side** — a client cannot substitute it.
The only thing a client influences is `SSH_ORIGINAL_COMMAND`, from which just
the first two words are taken and checked against a whitelist:

| Verb | Effect |
|---|---|
| `list` | print the `hostid`s this key is entitled to |
| `ping [hostid]` | `pong <hostid>` — connectivity test |
| `meta [hostid]` | `meta.json`: domains, serial, `not_after`, `fingerprint_sha256` |
| `sums [hostid]` | `SHA256SUMS` |
| `fetch [hostid]` | a `tar` stream with six files |

In every cycle the agent first asks for `meta` (a few hundred bytes) and only
downloads the rest when the fingerprint differs from the locally installed one.
At 40 hosts × 24 times a day that is still negligible traffic.

Verification on the agent side, before installing:

1. `sha256sum -c SHA256SUMS`
2. fingerprint of the downloaded `cert.pem` == fingerprint from `meta.json`
3. public key from the certificate == public key derived from `privkey.pem`
4. `openssl x509 -checkend 86400` — we do not install something about to expire
5. `openssl x509 -checkhost` for every expected name
6. atomic install (`.new.*` → `mv`), previous version kept in `$DEST/.previous`
7. `RELOAD_CMD`; if it returns an error → **rollback** to the previous certificate

---

## The private-key model

The key is generated on the certpull server and travels to the host inside the
SSH session. The consequences worth knowing:

* the server is a single point of compromise for all ~40 keys — treat it as a
  PKI host: its own project, a firewall, no other services, and
  `/var/lib/certpull` readable by root only
* back up `/var/lib/certpull/lego` (ACME account + certificates) and
  `/etc/certpull` — without them, recovery means reissuing everything
* if some host requires "the key never leaves this machine", a CSR mode can be
  added: the agent sends `csr` instead of `fetch`, the server feeds it to
  `lego --csr` and returns only the certificate. The structure of `pull-shell`
  is prepared for this (one more verb on the whitelist).

---

## Renewal and 45-day certificates

Let's Encrypt is shortening certificate lifetimes to 45 days. The default
`RENEW_DAYS=15` is about one third of the validity period, leaving a
three-week window to fix a failure before anything expires. The timer runs
twice a day with `RandomizedDelaySec=45m`.

The agent checks hourly, so at most ~1.5 h passes between a renewal on the
server and the replacement on the host. If a host was powered off,
`Persistent=true` catches the cycle up on the next boot.

---

## What about dns-persist-01?

Short answer: **it is not in Let's Encrypt production yet (as of August 2026)**,
so there is no point waiting for it.

* February 2026 — LE announces `dns-persist-01`: a single persistent
  `_validation-persist.<domain>` TXT record binding the domain to a specific
  ACME account and CA, after which no DNS changes are needed on renewal.
  Staging was announced for late Q1 2026, production for Q2 2026.
* April 2026 — draft-00, then draft-01, available in staging.
* June 2026 — LE states it **will not deploy to production** until an issue
  with client-computed data in the record is resolved; the draft is awaiting a
  larger `-02` update. `issuer-domain-names`/`caaIdentities` and wildcard
  handling remain unsettled.
* August 2026 — still no production deployment.

What this means for certpull: **nothing urgent.** The DNS-01 layer in this
project is isolated to a single thing — `lego --dns rfc2136` invoked from
`certpull-issue`. When `dns-persist-01` does reach production, the migration is:

1. insert one `_validation-persist` record per domain (or one with the wildcard
   flag for a whole subtree) — exactly where the CNAMEs sit today,
2. swap `--dns rfc2136` for the corresponding lego switch,
3. the server is no longer needed as a DNS server; Knot and the NS delegation
   can go, while `certpull-issue`, `pull-shell`, the agent and the whole SSH
   model **stay unchanged**.

The part that solves the actual problem — delivering a certificate to a machine
with no public address — is orthogonal to the challenge type and survives the
change.

Also worth keeping an eye on `dns-account-01` (the RFC'd variant that binds the
record name to an ACME account) — it tends to be deployed earlier than
`dns-persist-01`.

---

## Repository layout

```
server/
  install-server.sh          server installer (also --update)
  certpull.conf.example      → /etc/certpull/certpull.conf
  hosts.d/example.conf       → /etc/certpull/hosts.d/<hostid>.conf
  certpull-issue             → /usr/local/sbin/          (renewal + publishing)
  certpull-host              → /usr/local/sbin/          (add/key/cname/del/list/keys/doctor)
  certpull-zone              → /usr/local/sbin/          (add/list/show/del/soa-min)
  certpull-verify            → /usr/local/sbin/          (end-to-end delegation test)
  certpull-status            → /usr/local/sbin/
  certpull-pull-shell        → /usr/local/lib/certpull/  (forced command)
  knot.conf.example          → /etc/knot/knot.conf
  acme-zone.example          → /var/lib/knot/<zone>.zone
  systemd/certpull-renew.{service,timer}
agent/
  install-agent.sh           LAN host installer (--user, --reload-unit, --update)
  agent.conf.example         → /etc/certpull/agent.conf            (root mode)
  agent.conf.user.example    → ~/.config/certpull/agent.conf       (dedicated-user mode)
  agent.d.example/*.conf     → …/agent.d/*.conf   (several certificates)
  certpull-agent             → /usr/local/bin/
  systemd/certpull-agent.{service,timer}     root mode
  systemd/certpull-agent@.{service,timer}    dedicated-user mode
```

---

## Troubleshooting

**`lego` cannot find a server to update** — check that Knot is listening and
that the TSIG key matches:

```bash
knotc zone-status acme.example.com
nsupdate -y "hmac-sha256:certpull.:<secret>" <<< $'server 127.0.0.1\nupdate add test.acme.example.com. 60 TXT "x"\nsend'
dig @127.0.0.1 TXT test.acme.example.com
```

**`rfc2136: failed to insert: … code=REFUSED`** — the most common failure, and
it always means the same thing: **lego did not follow the CNAME** and tried to
update the original name, for which Knot is not authoritative. You can tell
because `fqdn=` in the message is `_acme-challenge.<your-domain>` rather than a
name in the delegated zone. Causes, in order of likelihood:

1. **The CNAME is missing** (not pasted, a typo, or not yet propagated).
2. **The resolver cannot see the CNAME** — because `/etc/resolv.conf` points at
   `127.0.0.1`, i.e. at Knot. Knot is authoritative, not recursive: it answers
   REFUSED, lego concludes there is no CNAME, and falls back to the original
   name.
3. Somebody set `LEGO_DISABLE_CNAME_SUPPORT` (following is **enabled** by
   default).

Diagnosis — two queries settle which cause it is:

```bash
dig +short CNAME _acme-challenge.host.example.com            # via the system resolver
dig @8.8.8.8 +short CNAME _acme-challenge.host.example.com   # via a public one
```

Both empty → the record does not exist (cause 1). The public one sees it and
the system one does not → a broken resolver (cause 2); fix
`/etc/resolv.conf`. Issuance itself works regardless, because `certpull-issue`
passes resolvers to lego explicitly via `DNS_RESOLVERS` in `certpull.conf` —
but the rest of the system then has broken DNS, so it is worth fixing anyway.

Rather than discovering this at `lego run`, check the delegation up front:

```bash
certpull-issue --preflight              # every host
certpull-issue --preflight srv-web-01   # one host
```

For each name the preflight checks that the CNAME exists and that its target
lives in a zone this Knot serves; on failure it prints the exact record to
paste and **does not call lego**, so you do not burn Let's Encrypt rate limits.
The same test runs automatically before every issuance and renewal
(`--skip-preflight` disables it, but there is no good reason to).

Authoritativeness is decided by the **`aa` flag, not the response status**. The
CNAME target almost never exists as a name — the TXT record lives only for the
few dozen seconds of validation — so `NXDOMAIN` with `aa` set is the correct,
expected result:

```
dig @127.0.0.1 SOA host.example.com.acme.example.com
;; ->>HEADER<<- ... status: NXDOMAIN
;; flags: qr aa rd            <- 'aa' = the zone is ours, all good
```

`REFUSED`, or `NXDOMAIN` **without** `aa`, means this Knot does not serve the
zone the CNAME points into — check `certpull-zone list`.

**`This account is currently not available.`** — the key **was accepted**;
authentication succeeded. This is `/usr/sbin/nologin` talking: sshd runs the
forced command through the user's **login shell** (`$SHELL -c '<command>'`), so
`nologin` kills the connection before `certpull-pull-shell` ever starts. The
`certpull` account needs a real shell:

```bash
usermod -s /bin/bash certpull
```

Security comes from `restrict` + `command=` in `authorized_keys`, not from the
shell — a client still cannot run anything outside the verb whitelist. The
account's password stays locked (`!`), so password login is impossible.

One command on the server checks this whole set of conditions:

```bash
certpull-host doctor
```

It verifies the account's shell and home directory, the permissions on `.ssh`
and `authorized_keys`, the presence of the forced command, the
`authorizedkeysfile` as sshd sees it, and the number of published certificates.

**LE says `No TXT record found at _acme-challenge...` even though lego reported
that propagation was fine** — that is not a contradiction, it is two different
tests:

* **lego** by default asks the **authoritative server directly** — that is our
  own Knot, which will of course answer "it is there". That proves nothing
  about the outside world.
* **Let's Encrypt** resolves the name **recursively**, from several network
  perspectives (MPIC). One hole in the public path is enough for it to see
  nothing.

Typical holes: the NS delegation has not propagated, or was never added; the NS
name has an **AAAA** record on which Knot does not answer (not listening on
`::@53`, or ufw not allowing 53 over IPv6) — resolvers try v6 and give up; a
geo filter or firewall cutting off some perspectives; a cached negative
NXDOMAIN from an earlier failed attempt.

That is why `certpull-issue` passes `--dns.propagation-rns` to lego — it moves
the check onto recursive resolvers, so a green result from lego starts to mean
something and we stop going to LE when the public path is broken.

For diagnosis there is a separate tool that reproduces exactly what LE does,
**without touching Let's Encrypt** (zero rate-limit usage):

```bash
certpull-verify srv-web-01      # one host
certpull-verify --all           # every host
certpull-verify smtp-relay.example.com
```

In order: it checks the CNAME, checks that **every** address (A *and* AAAA) of
the NS really answers, writes a test TXT via `nsupdate`/TSIG, queries four
public resolvers for it recursively through the CNAME, then deletes the test
record:

```
== authoritative servers of zone acme.example.com
    OK   ns-certpull.example.com. [203.0.113.10] answers authoritatively
    FAIL ns-certpull.example.com. [2001:db8::10] DOES NOT ANSWER -- that alone is
         enough for Let's Encrypt to fail validation
         IPv6 address. Is Knot listening on ::@53 and does ufw allow 53 over IPv6?
```

The zone templates set `minimum` (the negative TTL) to 60 s, so a cached
NXDOMAIN after a failed attempt does not block the next one for five minutes.
Zones created earlier may still have 300 — `certpull-zone soa-min <zone>` fixes
that on a live zone.

**`DNS update failed: … 127.0.0.1:53: i/o timeout`** — Knot is not answering
`UPDATE` even though it is running and serving the zone normally. The usual
cause: **the zone has an open transaction**. `knotc zone-begin` blocks dynamic
updates until `zone-commit` or `zone-abort`, and Knot does not reject them — it
simply stops answering, so lego only sees a timeout with no way to guess why.
It is left behind by an interrupted `zone-begin`.

```bash
knotc zone-status acme.example.com +transaction   # "open" = this is it
knotc zone-abort  acme.example.com                # or zone-commit
```

`certpull-issue --preflight` and `certpull-verify` check this themselves and
will not let lego run while a transaction is dangling. `certpull-zone soa-min`
closes its own transaction from a trap on every exit path, so it never leaves
one behind.

**Stale TXT records after an interrupted run** — `lego` issues `update add`,
not `replace`. When a run is interrupted while waiting for propagation (Ctrl-C,
a timeout, a killed process), the cleanup never happens and the old token
**stays in the zone**. The next attempt adds its own next to it, and resolvers
that cached the previous RRset keep serving it for its full TTL — so LE gets a
set without its own token and reports "No TXT record found", even though the
record is physically there.

One detail in `certpull-verify` gives it away: the CNAME target answers
**`NOERROR`** instead of `NXDOMAIN`. Between validations that name has no
business existing — `NOERROR` means something was left behind.

`certpull-issue` cleans this up itself before every validation
(`PURGE_STALE_TXT="yes"`):

```
_acme-challenge.app.example.com: removed 2 stale TXT record(s) left by an interrupted run
```

Set `PURGE_STALE_TXT="no"` only if you deliberately keep your own TXT records
under that name. `certpull-verify` also clears every TXT under the target —
that is intentional, not a side effect.

**Agent: `cannot fetch meta`** — step by step:

```bash
ssh -i /etc/certpull/id_ed25519 -o UserKnownHostsFile=/etc/certpull/known_hosts \
    certpull@ns-certpull.example.com ping
```

`Host key verification failed` → the server's host key changed (was the machine
rebuilt?). `Permission denied` → the key was never added with
`certpull-host key`. `no published certificate` → `certpull-issue` has not
succeeded on the server yet.

**Let's Encrypt rate limits** — 5 identical sets of names per week. Test
against staging; use `--force` on production sparingly.
