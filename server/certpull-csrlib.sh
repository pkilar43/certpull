# certpull-csrlib.sh -- CSR inspection and authorisation.
#
# Sourced by BOTH certpull-pull-shell (running as the unprivileged "certpull"
# SSH account) and certpull-issue (running as root). There is deliberately only
# one implementation: in CSR mode the name check below is the entire security
# boundary. With --csr, lego takes the names to validate FROM THE CSR and
# refuses --domains altogether, so if an agent could put arbitrary names into
# its CSR it could obtain a certificate for somebody else's domain.
#
# The rule: the set of names in the CSR must be EXACTLY the set of names in the
# host's DOMAINS -- not a subset, not a superset. A host that needs a different
# name gets it by having DOMAINS changed on the server, the same way the hostid
# itself is only ever written on the server side.
#
# Every function here is safe under `set -Eeuo pipefail`: no bare `&&` chains as
# the last command of a function, because that would make a false condition look
# like a failure and abort the caller.
#
# shellcheck shell=bash

# Maximum size of a submitted CSR. A P-256 CSR is ~450 bytes and an RSA-4096 one
# with a dozen SANs stays well under 4 KiB; 16 KiB is generous and bounds what an
# agent can write into CSR_DIR.
CERTPULL_CSR_MAX_BYTES="${CERTPULL_CSR_MAX_BYTES:-16384}"

csr_norm_stream() {
  # stdin: one name per line -> normalised, sorted, unique, on stdout.
  #
  # BOTH sides of the comparison go through this one function. If the CSR side
  # and the DOMAINS side were normalised even slightly differently, the check
  # would start passing or failing for the wrong reasons.
  sed -e 's/[[:space:]]//g' \
    | tr '[:upper:]' '[:lower:]' \
    | sed -e 's/\.$//' -e '/^$/d' \
    | LC_ALL=C sort -u
}

csr_names() {
  # $1 = CSR file -> the normalised set of names the CSR asks for.
  #
  # Both the CN and the DNS SANs count. certpull-agent always repeats the CN in
  # the SAN list, but a hand-made CSR may not, and a name present only in the CN
  # would otherwise slip past the check -- lego would still validate it, because
  # GetCSRMainDomain prefers the CN.
  #
  # The SANs are read from -text because openssl 3.0's `req` has no -ext option.
  # Grepping for every "DNS:" token rather than the line after the "Subject
  # Alternative Name" header means a wrapped or multi-line SAN list is handled
  # too; "DNS:" appears nowhere else in a CSR dump.
  local csr="$1" cn
  cn=$(openssl req -in "$csr" -noout -subject 2>/dev/null \
         | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p' | head -1) || cn=""
  {
    if [[ -n $cn ]]; then printf '%s\n' "$cn"; fi
    openssl req -in "$csr" -noout -text 2>/dev/null \
      | grep -o 'DNS:[^,[:space:]]*' | sed 's/^DNS://' || true
  } | csr_norm_stream
}

csr_cn() {
  # $1 = CSR file -> the normalised Subject CN, or empty when there is none.
  # lego builds its output file names from this (GetCSRMainDomain prefers the CN
  # over the first DNS SAN), so it decides which files certpull-issue has to
  # look for afterwards.
  openssl req -in "$1" -noout -subject 2>/dev/null \
    | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p' | head -1 | csr_norm_stream
}

csr_key_ok() {
  # $1 = CSR file. Returns 1 and explains on stderr when the key is one Let's
  # Encrypt would refuse -- better to say so here than to burn a failed order.
  local csr="$1" txt algo bits curve
  txt=$(openssl req -in "$csr" -noout -text 2>/dev/null) || {
    echo "the CSR cannot be parsed" >&2; return 1; }

  algo=$(printf '%s' "$txt"  | sed -n 's/.*Public Key Algorithm: *\(.*\)/\1/p'      | head -1) || algo=""
  bits=$(printf '%s' "$txt"  | sed -n 's/.*Public-Key: *(\([0-9]*\) bit).*/\1/p'    | head -1) || bits=""
  curve=$(printf '%s' "$txt" | sed -n 's/.*NIST CURVE: *\(.*\)/\1/p'                | head -1) || curve=""

  case "$algo" in
    *rsaEncryption*)
      if [[ -z $bits ]] || (( bits < 2048 )); then
        echo "RSA ${bits:-?} bit is too short -- Let's Encrypt requires at least 2048" >&2
        return 1
      fi
      if (( bits > 4096 )); then
        echo "RSA ${bits} bit is more than the 4096 Let's Encrypt accepts" >&2
        return 1
      fi
      ;;
    *ecPublicKey*)
      case "$curve" in
        P-256|P-384) ;;
        *) echo "EC curve ${curve:-?} is not accepted -- use P-256 or P-384" >&2; return 1 ;;
      esac
      ;;
    *)
      echo "unsupported key algorithm: ${algo:-?}" >&2
      return 1
      ;;
  esac
  return 0
}

csr_spki_sha256() {
  # $1 = CSR file -> sha256 of the DER SubjectPublicKeyInfo.
  # This is the value the agent compares against its own key: it is what ties a
  # published certificate to the private key that never left the LAN machine.
  openssl req -in "$1" -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex 2>/dev/null | sed 's/.*= *//'
}

cert_spki_sha256() {
  # $1 = certificate file -> the same digest, for comparison with a CSR or key.
  openssl x509 -in "$1" -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex 2>/dev/null | sed 's/.*= *//'
}

key_spki_sha256() {
  # $1 = private key file -> the same digest, derived from the private key.
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex 2>/dev/null | sed 's/.*= *//'
}

csr_check() {
  # $1 = CSR file, $2 = the authorised DOMAINS string.
  # 0 only when the CSR is well formed, correctly self-signed, carries a usable
  # key, and asks for exactly the authorised set of names. Diagnostics go to
  # stderr; success prints nothing.
  local csr="$1" allowed_raw="$2" want got
  local -a allowed=()

  if [[ ! -s $csr ]]; then echo "the CSR file is empty or missing" >&2; return 1; fi

  # The self-signature proves the submitter holds the matching private key. We
  # do not depend on that for authorisation -- the names do that -- but a CSR
  # failing it would be rejected by the CA anyway, with a much worse message.
  if ! openssl req -in "$csr" -noout -verify >/dev/null 2>&1; then
    echo "the CSR self-signature does not verify" >&2
    return 1
  fi

  if ! csr_key_ok "$csr"; then return 1; fi

  # `read -ra`, NOT an unquoted expansion: certpull-issue runs with
  # `shopt -s nullglob`, where a wildcard domain is pathname-expanded and
  # silently disappears from the list -- which would make this check compare
  # the CSR against a shorter set of names than the host is really authorised
  # for, and reject every wildcard host.
  read -r -a allowed <<<"$allowed_raw"
  want=$(printf '%s\n' "${allowed[@]}" | csr_norm_stream)
  got=$(csr_names "$csr")

  if [[ -z $got ]]; then
    echo "the CSR requests no names at all (neither a CN nor a DNS SAN)" >&2
    return 1
  fi
  if [[ $want != "$got" ]]; then
    echo "the names in the CSR are not the ones authorised for this host" >&2
    echo "  authorised: $(printf '%s' "$want" | tr '\n' ' ')" >&2
    echo "  in the CSR: $(printf '%s' "$got"  | tr '\n' ' ')" >&2
    return 1
  fi
  return 0
}
