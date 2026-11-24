# certpull-wwwlib.sh -- publishing the PUBLIC part of a certificate over HTTPS.
#
# Sourced by certpull-issue (which publishes) and certpull-host (which manages
# the per-host token and the URL). Not sourced by certpull-pull-shell: the SSH
# forced command has nothing to do with this path.
#
# WHY THIS NEEDS NO AUTHENTICATION AT ALL
#
# In CSR mode a published bundle contains no private key, and a certificate is
# public data -- it is already in Certificate Transparency. Its authenticity
# does not come from the channel: the agent accepts it only if it chains to
# Let's Encrypt AND matches the private key that never left that machine. So
# there is nothing here worth protecting with a credential, which is exactly
# why this transport needs no keys, no tokens-as-passwords and no accounts, and
# works through an HTTP proxy that only allows 443.
#
# WHAT THE TOKEN IS AND IS NOT
#
# The directory name is "<hostid>-<token>" with 128 random bits. That is NOT an
# authentication secret and nothing is allowed to depend on it being one. Its
# only job is to stop a stranger ENUMERATING the fleet: without it, anybody who
# guessed a hostid could read which internal host serves which customer names.
# Treat a leaked token as an information-disclosure annoyance, not a breach --
# and rotate it with `certpull-host token --rotate`.
#
# THE INVARIANT THAT MATTERS MOST HERE
#
# Only a host in CSR mode is ever published this way, and only an explicit list
# of files is copied -- never a glob. A full-mode bundle contains privkey.pem,
# and publishing that over anonymous HTTPS would hand out the private key to
# the entire internet. www_publish refuses it, twice, and would rather fail the
# host than guess.
#
# shellcheck shell=bash

# The only files that may ever be served. Explicit, not a glob: a glob would
# happily pick up a privkey.pem the day something else puts one there.
CERTPULL_WWW_FILES=( cert.pem chain.pem fullchain.pem meta.json SHA256SUMS )

www_enabled() {
  # HTTPS publishing is off unless a base URL is configured, so an existing
  # installation changes nothing when it is upgraded.
  [[ -n ${WWW_BASE_URL:-} ]]
}

www_new_token() {
  openssl rand -hex 16
}

www_token_of() {             # $1 = hostid -> the token from the host file, or empty
  local f="${HOSTS_DIR:?}/$1.conf"
  [[ -r $f ]] || return 0
  ( set +u
    WWW_TOKEN=""
    # shellcheck source=/dev/null
    source "$f" >/dev/null 2>&1 || exit 0
    printf '%s' "$WWW_TOKEN" )
}

www_set_token() {            # $1 = hostid, $2 = token ; rewrites the host file in place
  local hostid="$1" tok="$2" f="${HOSTS_DIR:?}/$1.conf"
  [[ -w $f ]] || { echo "cannot write $f" >&2; return 1; }
  if grep -qE '^[[:space:]]*WWW_TOKEN=' "$f"; then
    sed -i "s|^[[:space:]]*WWW_TOKEN=.*|WWW_TOKEN=\"$tok\"|" "$f"
  else
    printf '\n# Random path component for HTTPS publishing. Not a password --\n# see certpull-wwwlib.sh. Rotate with: certpull-host token --rotate %s\nWWW_TOKEN="%s"\n' \
      "$hostid" "$tok" >> "$f"
  fi
}

www_dirname() {              # $1 = hostid -> "<hostid>-<token>", or empty without a token
  local tok; tok="$(www_token_of "$1")"
  [[ -n $tok ]] || return 0
  printf '%s-%s' "$1" "$tok"
}

www_url() {                  # $1 = hostid -> the base URL the agent is configured with
  local d; d="$(www_dirname "$1")"
  [[ -n $d ]] || return 0
  printf '%s/%s' "${WWW_BASE_URL%/}" "$d"
}

www_remove() {               # $1 = hostid ; drops every directory belonging to it
  local base="${WWW_DIR:?}" d
  [[ -d $base ]] || return 0
  shopt -s nullglob
  for d in "$base/$1-"*; do
    [[ -d $d ]] && rm -rf "$d"
  done
  return 0
}

www_write_config() {         # $1 = hostid, $2 = DOMAINS, $3 = mode, $4 = key type
  # The HTTPS counterpart of the SSH "config" verb, and needed for the same
  # reason: an agent must be able to learn which names it is authorised for
  # BEFORE anything has been issued, otherwise it cannot build its first CSR.
  # Written early in the run, not at publish time -- after a DOMAINS change the
  # agent needs the new list in order to produce the CSR that unblocks the
  # issuance, so waiting for a successful issuance would deadlock.
  local hostid="$1" domains="$2" mode="$3" ktype="$4" dir tmp
  www_enabled || return 0
  [[ $mode == csr ]] || return 0
  dir="$(www_dirname "$hostid")"
  [[ -n $dir ]] || return 0
  install -d -m 0755 "${WWW_DIR:?}/$dir" || return 1
  tmp=$(mktemp "${WWW_DIR}/$dir/.config.XXXXXX") || return 1
  printf '{"hostid":"%s","mode":"%s","domains":"%s","key_type":"%s","generated":"%s"}\n' \
    "$hostid" "$mode" "$domains" "$ktype" "$(date -u +%FT%TZ)" > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$WWW_DIR/$dir/config.json"
}

www_publish() {              # $1 = hostid, $2 = source dir (the published pull dir), $3 = mode
  local hostid="$1" src="$2" mode="$3" dir tmp f
  www_enabled || return 0

  # Guard one: only CSR mode. A full-mode bundle holds privkey.pem.
  if [[ $mode != csr ]]; then return 0; fi

  dir="$(www_dirname "$hostid")"
  if [[ -z $dir ]]; then
    echo "WWW: $hostid has no WWW_TOKEN -- add one with: certpull-host token $hostid" >&2
    return 0
  fi

  # Guard two: refuse outright if anything key-shaped is in the source. This
  # should be impossible -- certpull-issue does not write one in CSR mode -- but
  # the cost of being wrong here is handing a private key to the internet.
  for f in privkey.pem combined.pem "$hostid.key"; do
    if [[ -e $src/$f ]]; then
      echo "WWW: REFUSING to publish $hostid over HTTPS -- $f is present in $src" >&2
      return 1
    fi
  done

  install -d -m 0755 "${WWW_DIR:?}" || return 1
  tmp=$(mktemp -d "${WWW_DIR}/.$hostid.XXXXXX") || return 1
  for f in "${CERTPULL_WWW_FILES[@]}"; do
    if [[ -s $src/$f ]]; then install -m 0644 "$src/$f" "$tmp/$f" || { rm -rf "$tmp"; return 1; }; fi
  done
  # config.json is per-host, not per-certificate: carry the existing one over so
  # the swap below does not momentarily remove it.
  if [[ -s $WWW_DIR/$dir/config.json ]]; then
    install -m 0644 "$WWW_DIR/$dir/config.json" "$tmp/config.json"
  fi
  chmod 0755 "$tmp"

  rm -rf "${WWW_DIR:?}/$dir.old"
  if [[ -d $WWW_DIR/$dir ]]; then mv "$WWW_DIR/$dir" "$WWW_DIR/$dir.old"; fi
  mv "$tmp" "$WWW_DIR/$dir"
  rm -rf "${WWW_DIR:?}/$dir.old"
  return 0
}

www_orphans() {
  # Directories under WWW_DIR that no host's current token claims. They appear
  # after a token rotation that could not finish, or a host removed by hand.
  local base="${WWW_DIR:-}" d name want
  [[ -n $base && -d $base ]] || return 0
  shopt -s nullglob
  for d in "$base"/*; do
    [[ -d $d ]] || continue
    name=$(basename "$d")
    [[ $name == .* ]] && continue
    want=""
    for f in "${HOSTS_DIR:?}"/*.conf; do
      if [[ "$(www_dirname "$(basename "$f" .conf)")" == "$name" ]]; then want=1; break; fi
    done
    [[ -n $want ]] || printf '%s\n' "$name"
  done
  return 0
}
