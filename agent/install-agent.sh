#!/usr/bin/env bash
# install-agent.sh -- install the certpull agent on a LAN machine.
#
# The server address is optional -- it defaults to
# certpull@ns-certpull.example.com (the same name that serves the NS
# delegation, so it always resolves).
#
# Root mode (certificates in /etc/ssl/certpull, key in /etc/certpull):
#   ./install-agent.sh srv-web-01
#   ./install-agent.sh srv-web-01 certpull@other-host.example.com
#
# Dedicated-user mode (key in ~/.ssh, certificates in ~/certificates):
#   ./install-agent.sh --user certpull srv-web-01
#   ./install-agent.sh --user certpull --reload-unit nginx srv-web-01
#
# --reload-unit <service>  writes a sudo rule letting that user run
#                          ONLY `systemctl reload <service>`
#
# Update after changes in the repository -- replaces ONLY the script and the
# units; it does not touch the configuration, the SSH key or known_hosts:
#   ./install-agent.sh --update
#   ./install-agent.sh --update --user certpull
#   ./install-agent.sh --update --dry-run
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"

# Default address of the certpull server. Deliberately ns-certpull.<domain>
# rather than some made-up name: that name MUST exist, because the NS
# delegation of the acme zone points at it -- so it always resolves and always
# points at the right machine.
DEFAULT_SERVER="${CERTPULL_DEFAULT_SERVER:-certpull@ns-certpull.example.com}"
[[ $EUID -eq 0 ]] || { echo "run as root (the agent itself will later run as an ordinary user)" >&2; exit 1; }

AGENT_USER=""; RELOAD_UNIT=""; MODE=install; DRY=0
while [[ ${1:-} == --* ]]; do
  case "$1" in
    --user)        AGENT_USER="${2:?}"; shift 2 ;;
    --reload-unit) RELOAD_UNIT="${2:?}"; shift 2 ;;
    --update)      MODE=update; shift ;;
    --dry-run)     DRY=1; shift ;;
    -h|--help)     sed -n '2,24p' "$0"; exit 0 ;;
    *)             echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

run() { if (( DRY )); then printf '   [dry-run] %s\n' "$*"; else "$@"; fi; }

# Keys that may be seeded into an existing agent.conf from the template.
# HOSTID, SERVER, DEST and RELOAD_CMD are host-specific -- only reported.
AGENT_SAFE_SEED=( FILE_STYLE DEST_MODE CERT_MODE KEY_MODE COMBINED EXPECT_DOMAINS
                  SERVER_PORT CERT_OWNER KEY_OWNER )

check_agent_conf() {          # $1 = config file  $2 = template
  local live="$1" tpl="$2" key line missing_safe=() missing_manual=()
  [[ -s $live ]] || return 0
  while IFS= read -r line; do
    key="${line%%=*}"
    if grep -qE "^[[:space:]]*${key}=" "$live"; then continue; fi
    if printf '%s\n' "${AGENT_SAFE_SEED[@]}" | grep -qx "$key"; then
      missing_safe+=( "$line" )
    else
      missing_manual+=( "$line" )
    fi
  done < <(grep -E '^[A-Z_]+=' "$tpl")

  if ((${#missing_safe[@]} == 0 && ${#missing_manual[@]} == 0)); then
    printf '   %s has every key\n' "$live"; return 0
  fi
  if ((${#missing_safe[@]})); then
    printf '   %s -- seeding defaults:\n' "$live"
    printf '     %s\n' "${missing_safe[@]}"
    if (( ! DRY )); then
      cp -a "$live" "$live.bak.$(date +%Y%m%d%H%M%S)"
      {
        printf '\n# --- appended by install-agent.sh --update (%s) ---\n' "$(date -u +%F)"
        printf '%s\n' "${missing_safe[@]}"
      } >> "$live"
    fi
  fi
  if ((${#missing_manual[@]})); then
    printf '   NOTE: set these BY HAND in %s:\n' "$live"
    printf '     %s\n' "${missing_manual[@]}"
  fi
}

if [[ $MODE == update ]]; then
  printf '\n==> updating the agent script\n'
  bash -n "$SRC/certpull-agent" || { echo "certpull-agent fails bash -n" >&2; exit 1; }
  run install -m 0755 "$SRC/certpull-agent" /usr/local/bin/certpull-agent
  run ln -sf /usr/local/bin/certpull-agent /usr/local/sbin/certpull-agent
  echo "   /usr/local/bin/certpull-agent"

  printf '\n==> systemd units\n'
  changed=0
  for u in certpull-agent.service certpull-agent.timer \
           certpull-agent@.service certpull-agent@.timer; do
    [[ -e /etc/systemd/system/$u ]] || continue      # only refresh units that are already installed
    if ! cmp -s "$SRC/systemd/$u" "/etc/systemd/system/$u"; then
      run install -m 0644 "$SRC/systemd/$u" "/etc/systemd/system/$u"; changed=1
      echo "   $u"
    fi
  done
  if (( changed )); then run systemctl daemon-reload; else echo "   unchanged"; fi

  printf '\n==> configuration\n'
  if [[ -n $AGENT_USER ]]; then
    if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
      echo "   user '$AGENT_USER' does not exist on this host" >&2
      echo "   (without --user I look for root's configuration in /etc/certpull)" >&2
      exit 1
    fi
    UHOME=$(getent passwd "$AGENT_USER" | cut -d: -f6)
    CDIR="$UHOME/.config/certpull"; TPL="$SRC/agent.conf.user.example"
  else
    CDIR="/etc/certpull"; TPL="$SRC/agent.conf.example"
  fi
  shopt -s nullglob
  found=0
  for c in "$CDIR/agent.conf" "$CDIR"/agent.d/*.conf; do
    [[ -s $c ]] || continue
    found=1; check_agent_conf "$c" "$TPL"
  done
  (( found )) || echo "   found no agent.conf at all in $CDIR (wrong --user?)"

  cat <<EOF

============================================================================
 Agent updated. NOT touched: the SSH key, known_hosts, the timers.

 Check with:
   $( [[ -n $AGENT_USER ]] && echo "runuser -u $AGENT_USER -- certpull-agent --check" || echo "certpull-agent --check" )
============================================================================
EOF
  exit 0
fi

HOSTID="${1:?give the hostid, e.g. srv-web-01}"
SERVER="${2:-$DEFAULT_SERVER}"
PORT="${3:-22}"

say() { printf '\n==> %s\n' "$*"; }

if [[ -z ${2:-} ]]; then
  say "server: $SERVER  (default -- pass a 2nd argument to change it)"
fi

say "packages"
# We do not call apt-get blindly: on a host with stale package lists it can
# fail even though every tool we need is already present, taking the whole
# installation down with it. So we first check what is actually missing.
missing=()
for c in ssh-keygen ssh-keyscan openssl tar; do
  command -v "$c" >/dev/null || missing+=( "$c" )
done
if ((${#missing[@]} == 0)); then
  echo "   ssh-keygen, ssh-keyscan, openssl, tar -- all present"
elif command -v apt-get >/dev/null; then
  echo "   missing: ${missing[*]} -- installing"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openssh-client openssl tar >/dev/null || true
  still=()
  for c in "${missing[@]}"; do command -v "$c" >/dev/null || still+=( "$c" ); done
  if ((${#still[@]})); then
    echo "apt-get did not install: ${still[*]} -- do it by hand and run this again" >&2
    exit 1
  fi
else
  echo "missing: ${missing[*]}, and there is no apt-get -- install them by hand" >&2
  exit 1
fi

say "script"
install -m 0755 "$SRC/certpull-agent" /usr/local/bin/certpull-agent
ln -sf /usr/local/bin/certpull-agent /usr/local/sbin/certpull-agent

# ============================================================================
if [[ -n $AGENT_USER ]]; then
# ------------------------------------------------------- dedicated-user mode
  say "user $AGENT_USER"
  if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "/var/lib/$AGENT_USER" \
            --shell /bin/bash --comment "certpull agent" "$AGENT_USER"
  fi
  UHOME=$(getent passwd "$AGENT_USER" | cut -d: -f6)
  [[ -d $UHOME ]] || { install -d -m 0750 -o "$AGENT_USER" -g "$AGENT_USER" "$UHOME"; }

  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$UHOME/.ssh"
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$UHOME/certificates"
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$UHOME/.cache/certpull"
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$UHOME/.config/certpull"

  KEY="$UHOME/.ssh/id_ed25519"
  KNOWN="$UHOME/.ssh/known_hosts"
  CONF="$UHOME/.config/certpull/agent.conf"
  TEMPLATE="$SRC/agent.conf.user.example"
  RUNAS=( runuser -u "$AGENT_USER" -- )
  UNIT="certpull-agent@$AGENT_USER"
else
# ------------------------------------------------------------------ root mode
  say "directories"
  install -d -m 0750 /etc/certpull
  install -d -m 0755 /etc/ssl/certpull
  KEY=/etc/certpull/id_ed25519
  KNOWN=/etc/certpull/known_hosts
  CONF=/etc/certpull/agent.conf
  TEMPLATE="$SRC/agent.conf.example"
  RUNAS=()
  UNIT="certpull-agent"
  AGENT_USER="root"
fi
# ============================================================================

say "SSH key"
if [[ ! -s $KEY ]]; then
  "${RUNAS[@]}" ssh-keygen -q -t ed25519 -N '' -f "$KEY" \
    -C "certpull-$HOSTID@$(hostname -f 2>/dev/null || hostname)"
fi
chmod 0600 "$KEY"; chmod 0644 "$KEY.pub"
if [[ $AGENT_USER != root ]]; then chown "$AGENT_USER:$AGENT_USER" "$KEY" "$KEY.pub"; fi

say "pinning the server's host key"
HOSTPART="${SERVER#*@}"
if [[ ! -s $KNOWN ]] || ! ssh-keygen -F "$HOSTPART" -f "$KNOWN" >/dev/null 2>&1; then
  # ssh-keyscan output goes to a temporary file first. Appending straight into
  # known_hosts would mean an unreachable server (wrong name, closed port, no
  # route) leaves junk or nothing there, and the script only blows up a few
  # lines later with "is not a public key file".
  scan=$(mktemp)
  if ! ssh-keyscan -p "$PORT" -t ed25519,rsa "$HOSTPART" > "$scan" 2>/dev/null \
     || [[ ! -s $scan ]]; then
    rm -f "$scan"
    cat >&2 <<EOF

ERROR: cannot fetch the host key from ${HOSTPART}:${PORT}

  Check, in order:
    getent hosts $HOSTPART            # does the name resolve
    nc -vz $HOSTPART $PORT            # is the port reachable from here
  If the server lives under a different name, pass it as the 2nd argument:
    $0 $HOSTID certpull@<host>
EOF
    exit 1
  fi
  cat "$scan" >> "$KNOWN"
  rm -f "$scan"
  chmod 0644 "$KNOWN"
  if [[ $AGENT_USER != root ]]; then chown "$AGENT_USER:$AGENT_USER" "$KNOWN"; fi
  echo "Host key stored (COMPARE this with the fingerprint on the server!):"
  ssh-keygen -lf "$KNOWN" || echo "  (cannot print the fingerprints -- check $KNOWN by hand)"
  echo "On the server:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
fi

say "configuration"
if [[ ! -s $CONF ]]; then
  sed -e "s|^SERVER=.*|SERVER=\"$SERVER\"|" \
      -e "s|^SERVER_PORT=.*|SERVER_PORT=\"$PORT\"|" \
      -e "s|^HOSTID=.*|HOSTID=\"$HOSTID\"|" \
      "$TEMPLATE" > "$CONF"
  chmod 0640 "$CONF"
  if [[ $AGENT_USER != root ]]; then chown "$AGENT_USER:$AGENT_USER" "$CONF"; fi
  echo "created $CONF"
fi

if [[ -n $RELOAD_UNIT && $AGENT_USER != root ]]; then
  say "sudo rule: systemctl reload $RELOAD_UNIT"
  SUDOERS="/etc/sudoers.d/certpull-agent-$AGENT_USER"
  printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl reload %s\n' \
    "$AGENT_USER" "$RELOAD_UNIT" > "$SUDOERS"
  chmod 0440 "$SUDOERS"
  visudo -cf "$SUDOERS" >/dev/null || { rm -f "$SUDOERS"; echo "the sudo rule was rejected" >&2; exit 1; }
  sed -i "s|^RELOAD_CMD=.*|RELOAD_CMD=\"sudo -n /usr/bin/systemctl reload $RELOAD_UNIT\"|" "$CONF"
  echo "$SUDOERS + RELOAD_CMD in $CONF"
fi

say "timer"
if [[ $AGENT_USER == root ]]; then
  install -m 0644 "$SRC/systemd/certpull-agent.service" /etc/systemd/system/
  install -m 0644 "$SRC/systemd/certpull-agent.timer"   /etc/systemd/system/
else
  install -m 0644 "$SRC/systemd/certpull-agent@.service" /etc/systemd/system/
  install -m 0644 "$SRC/systemd/certpull-agent@.timer"   /etc/systemd/system/
fi
systemctl daemon-reload
systemctl enable --now "${UNIT}.timer"

cat <<EOF

============================================================================
 Agent installed  (user: $AGENT_USER)

   config        $CONF
   key           $KEY
   certificates  $( [[ $AGENT_USER == root ]] && echo /etc/ssl/certpull || echo "$UHOME/certificates" )
   timer         ${UNIT}.timer

 On the SERVER run:

   certpull-host add $HOSTID <domain> [more domains...]
   certpull-host key $HOSTID "$(cat "$KEY.pub")"

 Several certificates on this host -- the hostid list overwrites the previous one:
   certpull-host key $HOSTID,<other-hostid> "$(cat "$KEY.pub")"
 and here, use profiles instead of agent.conf:
   $(dirname "$CONF")/agent.d/*.conf

 Then back here:
   $( [[ $AGENT_USER == root ]] && echo "certpull-agent --check" || echo "runuser -u $AGENT_USER -- certpull-agent --check" )
   systemctl list-timers ${UNIT}.timer
============================================================================
EOF
