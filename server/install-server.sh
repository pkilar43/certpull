#!/usr/bin/env bash
# install-server.sh -- install and update the certpull server.
# (Debian 12/13 or Ubuntu 24.04). Run as root from the repository directory.
#
# First install (clean machine):
#   ./install-server.sh acme.example.com ns-certpull.example.com pki@example.com
#
# Update after changes in the repository -- replaces ONLY the scripts and the
# systemd units; it does not touch the configuration, Knot, sshd, ufw or the
# certpull account:
#   ./install-server.sh --update
#   ./install-server.sh --update --dry-run     show what it would do
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
LEGO_VERSION="${LEGO_VERSION:-4.31.0}"
CONF_LIVE="/etc/certpull/certpull.conf"

MODE=install; DRY=0
while [[ ${1:-} == --* ]]; do
  case "$1" in
    --update)  MODE=update; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
run() { if (( DRY )); then printf '   [dry-run] %s\n' "$*"; else "$@"; fi; }

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

# --- server scripts: one source of truth for both modes ---------------------
SBIN_SCRIPTS=( certpull-issue certpull-status certpull-host certpull-zone certpull-verify )
LIB_SCRIPTS=( certpull-pull-shell )
UNITS=( certpull-renew.service certpull-renew.timer )

# Keys that may be seeded automatically into an existing certpull.conf using
# the value from the template. The condition: the template value is a sensible
# default for EVERY installation. Keys that depend on the particular deployment
# (ACME_ZONE, ACME_NS_NAME, ACME_EMAIL, paths) are only reported.
SAFE_SEED=( DNS_RESOLVERS PROPAGATION_RNS PROPAGATION_WAIT PURGE_STALE_TXT
            RENEW_DAYS DEFAULT_KEY_TYPE LOG_TAG )

install_scripts() {
  local f
  for f in "${SBIN_SCRIPTS[@]}"; do
    bash -n "$SRC/$f" || { echo "$f fails bash -n -- aborting" >&2; exit 1; }
    run install -m 0755 "$SRC/$f" "/usr/local/sbin/$f"
  done
  for f in "${LIB_SCRIPTS[@]}"; do
    bash -n "$SRC/$f" || { echo "$f fails bash -n -- aborting" >&2; exit 1; }
    run install -d -m 0755 /usr/local/lib/certpull
    run install -m 0755 "$SRC/$f" "/usr/local/lib/certpull/$f"
  done
  printf '   installed: %s %s\n' "${SBIN_SCRIPTS[*]}" "${LIB_SCRIPTS[*]}"
}

install_units() {
  local u changed=0
  for u in "${UNITS[@]}"; do
    if ! cmp -s "$SRC/systemd/$u" "/etc/systemd/system/$u"; then
      run install -m 0644 "$SRC/systemd/$u" "/etc/systemd/system/$u"
      changed=1
    fi
  done
  if (( changed )); then run systemctl daemon-reload; printf '   systemd units updated\n'
  else printf '   systemd units unchanged\n'; fi
}

check_config_keys() {         # compares the template's keys with the live config
  [[ -s $CONF_LIVE ]] || { echo "   $CONF_LIVE is missing -- skipping"; return 0; }
  local key line missing_safe=() missing_manual=()
  while IFS= read -r line; do
    key="${line%%=*}"
    if grep -qE "^[[:space:]]*${key}=" "$CONF_LIVE"; then continue; fi
    if printf '%s\n' "${SAFE_SEED[@]}" | grep -qx "$key"; then
      missing_safe+=( "$line" )
    else
      missing_manual+=( "$line" )
    fi
  done < <(grep -E '^[A-Z_]+=' "$SRC/certpull.conf.example")

  if ((${#missing_safe[@]} == 0 && ${#missing_manual[@]} == 0)); then
    printf '   %s has every key\n' "$CONF_LIVE"
    return 0
  fi

  if ((${#missing_safe[@]})); then
    printf '   seeding the missing keys (values = defaults, behaviour unchanged):\n'
    printf '     %s\n' "${missing_safe[@]}"
    if (( ! DRY )); then
      cp -a "$CONF_LIVE" "$CONF_LIVE.bak.$(date +%Y%m%d%H%M%S)"
      {
        printf '\n# --- appended by install-server.sh --update (%s) ---\n' "$(date -u +%F)"
        printf '%s\n' "${missing_safe[@]}"
      } >> "$CONF_LIVE"
    fi
  fi
  if ((${#missing_manual[@]})); then
    printf '   NOTE: these keys depend on the deployment -- set them BY HAND in %s:\n' "$CONF_LIVE"
    printf '     %s\n' "${missing_manual[@]}"
  fi
}

# ============================================================================
if [[ $MODE == update ]]; then
  say "updating the scripts"
  install_scripts
  say "systemd units"
  install_units
  say "configuration"
  check_config_keys
  cat <<EOF

============================================================================
 Scripts and units updated. NOT touched: certpull.conf (beyond seeding the
 missing keys), knot.conf, the zones, sshd, ufw, the certpull account, timers.

 Check that everything still works:
   certpull-host doctor
   certpull-issue --preflight
   certpull-status
============================================================================
EOF
  exit 0
fi
# ============================================================================

ACME_ZONE="${1:?give the delegated zone, e.g. acme.example.com}"
NS_NAME="${2:?give the NS name pointing at this host, e.g. ns-certpull.example.com}"
EMAIL="${3:?give the e-mail address for the ACME account}"

# --- packages ---------------------------------------------------------------
say "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  knot knot-dnsutils openssl ca-certificates curl tar dnsutils jq ufw

# --- lego -------------------------------------------------------------------
if ! command -v lego >/dev/null 2>&1; then
  say "lego v$LEGO_VERSION"
  arch=$(dpkg --print-architecture)
  case "$arch" in
    amd64) larch=amd64 ;; arm64) larch=arm64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
  esac
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/lego.tgz" \
    "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_${larch}.tar.gz"
  tar -C "$tmp" -xzf "$tmp/lego.tgz" lego
  install -m 0755 "$tmp/lego" /usr/local/bin/lego
  rm -rf "$tmp"
fi
lego --version

# --- user and directories ---------------------------------------------------
say "certpull user + directories"
# NOTE: the shell MUST be a real one (/bin/bash), not /usr/sbin/nologin.
# sshd runs the forced command through the user's login shell
# ("$SHELL -c '<command>'"), so nologin would cut the connection short with
# "This account is currently not available." before pull-shell ever starts.
# Security comes from `restrict` + `command=` in authorized_keys, not the shell.
if ! id -u certpull >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/certpull --shell /bin/bash \
          --comment "certpull SSH pull account" certpull
else
  cur_shell=$(getent passwd certpull | cut -d: -f7)
  case "$cur_shell" in
    */nologin|*/false)
      say "fixing the shell of the certpull account ($cur_shell -> /bin/bash)"
      usermod -s /bin/bash certpull
      ;;
  esac
fi
# The password stays locked ("!" from useradd --system) -- key-based login
# still works, password login does not.
install -d -m 0755 -o root -g root /etc/certpull /etc/certpull/hosts.d
install -d -m 0755 -o root -g root /usr/local/lib/certpull
install -d -m 0750 -o certpull -g certpull /var/lib/certpull
install -d -m 0700 -o certpull -g certpull /var/lib/certpull/.ssh
install -d -m 0700 -o root -g root /var/lib/certpull/lego
install -d -m 0711 -o root -g certpull /var/lib/certpull/pull
touch /var/lib/certpull/.ssh/authorized_keys
chown certpull:certpull /var/lib/certpull/.ssh/authorized_keys
chmod 0600 /var/lib/certpull/.ssh/authorized_keys

# --- scripts ----------------------------------------------------------------
say "scripts"
install_scripts

# --- TSIG -------------------------------------------------------------------
say "TSIG key"
if [[ ! -s /etc/certpull/tsig.env ]]; then
  SECRET=$(openssl rand -base64 32)
  cat > /etc/certpull/tsig.env <<EOF
TSIG_NAME="certpull."
TSIG_ALG="hmac-sha256."
TSIG_SECRET="$SECRET"
EOF
  chmod 0600 /etc/certpull/tsig.env
else
  # shellcheck source=/dev/null
  source /etc/certpull/tsig.env
  SECRET="$TSIG_SECRET"
fi

# --- certpull configuration -------------------------------------------------
if [[ ! -s /etc/certpull/certpull.conf ]]; then
  say "/etc/certpull/certpull.conf"
  sed -e "s|^ACME_EMAIL=.*|ACME_EMAIL=\"$EMAIL\"|" \
      -e "s|^ACME_ZONE=.*|ACME_ZONE=\"$ACME_ZONE\"|" \
      -e "s|^ACME_NS_NAME=.*|ACME_NS_NAME=\"$NS_NAME\"|" \
      "$SRC/certpull.conf.example" > /etc/certpull/certpull.conf
  chmod 0640 /etc/certpull/certpull.conf
else
  say "/etc/certpull/certpull.conf already exists -- leaving it alone"
fi

# --- Knot -------------------------------------------------------------------
# The installer configures Knot ONLY on the first run. Further zones are added
# with `certpull-zone add`, so the ones already working are never lost.
if grep -q "acl_certpull_update" /etc/knot/knot.conf 2>/dev/null; then
  say "Knot is already configured by certpull -- skipping"
  echo "    add another zone with:  certpull-zone add <zone> [ns-name]"
else
  say "Knot DNS (zone $ACME_ZONE)"
  if [[ ! -f /etc/knot/knot.conf.orig ]]; then
    cp -a /etc/knot/knot.conf /etc/knot/knot.conf.orig 2>/dev/null || true
  fi
  # The placeholders below MUST stay in sync with knot.conf.example and
  # acme-zone.example. If a template is renamed to a different domain without
  # updating these patterns, sed silently matches nothing and the generated
  # files keep the template's domain instead of the one passed in $1.
  sed -e "s|acme\.example\.com|$ACME_ZONE|g" \
      -e "s|REPLACE_ME_WITH_KEYMGR_OUTPUT|$SECRET|" \
      "$SRC/knot.conf.example" > /etc/knot/knot.conf
  chown root:knot /etc/knot/knot.conf
  chmod 0640 /etc/knot/knot.conf

  ZONEFILE="/var/lib/knot/${ACME_ZONE}.zone"
  if [[ ! -s $ZONEFILE ]]; then
    sed -e "s|ns-certpull\.example\.com|$NS_NAME|g" \
        -e "s|pki\.example\.com|${EMAIL/@/.}|g" \
        -e "s|acme\.example\.com|$ACME_ZONE|g" \
        "$SRC/acme-zone.example" > "$ZONEFILE"
    chown knot:knot "$ZONEFILE"
    chmod 0640 "$ZONEFILE"
  fi

  knotc conf-check
  systemctl enable --now knot
  systemctl restart knot
  sleep 1
  knotc zone-status "$ACME_ZONE" || true
fi

# --- resolver ---------------------------------------------------------------
say "resolver"
if grep -qE '^nameserver[[:space:]]+(127\.0\.0\.1|::1)[[:space:]]*$' /etc/resolv.conf 2>/dev/null; then
  cat >&2 <<'EOF'
  WARNING: /etc/resolv.conf points at 127.0.0.1, but this host runs Knot,
  which is authoritative and NOT recursive -- it answers REFUSED to anything
  outside its own zones. lego would then fail to resolve the _acme-challenge
  CNAME and try to update the original name instead (the "code=REFUSED" error).
  certpull passes resolvers explicitly via DNS_RESOLVERS in certpull.conf, so
  issuing itself will work, but the rest of the system has broken DNS.
  Fix resolv.conf -- on DigitalOcean, for example: 67.207.67.2, 67.207.67.3
EOF
fi

# --- sshd: the pull account, forced command only ----------------------------
say "sshd"
cat > /etc/ssh/sshd_config.d/50-certpull.conf <<'EOF'
Match User certpull
    PasswordAuthentication no
    PermitTTY no
    X11Forwarding no
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTunnel no
    AuthorizedKeysFile /var/lib/certpull/.ssh/authorized_keys
    ClientAliveInterval 30
EOF
sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd

# --- systemd ----------------------------------------------------------------
say "timer"
install_units
systemctl enable --now certpull-renew.timer

# --- firewall ---------------------------------------------------------------
say "ufw"
ufw allow 22/tcp   >/dev/null
ufw allow 53/udp   >/dev/null
ufw allow 53/tcp   >/dev/null
ufw --force enable >/dev/null
ufw status numbered

# --- summary ----------------------------------------------------------------
IP4=$(curl -fsS4 https://ifconfig.co 2>/dev/null || hostname -I | awk '{print $1}')
IP6=$(curl -fsS6 https://ifconfig.co 2>/dev/null || true)

cat <<EOF

============================================================================
 The certpull server is ready.

 1) In the parent zone (at your domain's DNS operator) add:

      ${NS_NAME}.   3600  IN  A     ${IP4}
$( [[ -n $IP6 ]] && printf '      %s.   3600  IN  AAAA  %s\n' "$NS_NAME" "$IP6" )
      ${ACME_ZONE}.   3600  IN  NS    ${NS_NAME}.

    Recommended (limits who may issue certificates for your domains):
      <domain>.  IN  CAA  0 issue "letsencrypt.org"

 2) Check the delegation (may take up to the parent zone's TTL):
      dig +trace SOA ${ACME_ZONE}
      dig @${IP4} SOA ${ACME_ZONE}

 3) Add the first host:
      certpull-host add srv-web-01 app.example.com www.app.example.com
      # paste the CNAME records it prints into the public zone
      certpull-host key srv-web-01 "\$(cat /tmp/srv-web-01.pub)"

 4) Test against staging before going to production:
      sed -i 's|acme-v02|acme-staging-v02|' /etc/certpull/certpull.conf
      certpull-issue srv-web-01
      # then switch back to production and delete /var/lib/certpull/lego/accounts

============================================================================
EOF
