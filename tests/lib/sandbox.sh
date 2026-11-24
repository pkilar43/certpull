#!/usr/bin/env bash
# Builds a throwaway "server + agent" sandbox for certpull with stubs for lego,
# dig, nsupdate, knotc and ssh. Nothing here touches a real ACME server.
set -Eeuo pipefail

REPO="${REPO:?set REPO to the repository root}"
T="${T:?set T to the sandbox root}"

rm -rf "$T"
mkdir -p "$T"/{bin,etc/certpull/hosts.d,var/lib/certpull/{pull,lego/certificates,csr},ca,agent,agenthome}

# --------------------------------------------------------------- test CA ----
openssl ecparam -name prime256v1 -genkey -noout -out "$T/ca/ca.key" 2>/dev/null
openssl req -x509 -new -key "$T/ca/ca.key" -days 3650 -subj "/CN=certpull test CA" \
  -out "$T/ca/ca.crt" 2>/dev/null
# an intermediate, so fullchain has something real in it
openssl ecparam -name prime256v1 -genkey -noout -out "$T/ca/int.key" 2>/dev/null
openssl req -new -key "$T/ca/int.key" -subj "/CN=certpull test intermediate" -out "$T/ca/int.csr" 2>/dev/null
cat > "$T/ca/int.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,digitalSignature,cRLSign,keyCertSign
EOF
openssl x509 -req -in "$T/ca/int.csr" -CA "$T/ca/ca.crt" -CAkey "$T/ca/ca.key" \
  -set_serial 2 -days 3650 -extfile "$T/ca/int.ext" -out "$T/ca/int.crt" 2>/dev/null

# ------------------------------------------------------------- lego stub ----
# Mimics the real thing closely enough to catch interface mistakes:
#  * --csr and --domains together is fatal (lego: "but not both")
#  * with --csr it writes .crt/.issuer.crt/.json and NO .key
#  * output file name comes from the CSR's CN, falling back to the first SAN
#  * '*' in the name becomes '_'
cat > "$T/bin/lego" <<'LEGO'
#!/usr/bin/env bash
set -Eeuo pipefail
CSR=""; PATHD=""; KEYTYPE="ec256"; DAYS=""; SUB=""
declare -a DOMS=()
while (($#)); do
  case "$1" in
    --csr|-c)    CSR="$2"; shift 2 ;;
    --domains|-d) DOMS+=( "$2" ); shift 2 ;;
    --path)      PATHD="$2"; shift 2 ;;
    --key-type)  KEYTYPE="$2"; shift 2 ;;
    --days)      DAYS="$2"; shift 2 ;;
    --accept-tos|--no-random-sleep|--dns.propagation-rns) shift ;;
    --email|--server|--dns|--dns.resolvers|--dns.propagation-wait) shift 2 ;;
    run|renew)   SUB="$1"; shift ;;
    *) echo "lego stub: unknown arg $1" >&2; exit 90 ;;
  esac
done
[[ -n $SUB ]] || { echo "lego stub: no subcommand" >&2; exit 91; }
if [[ -n $CSR ]] && ((${#DOMS[@]})); then
  echo "Please specify either --domains/-d or --csr/-c, but not both" >&2; exit 1
fi
if [[ -z $CSR ]] && ((${#DOMS[@]} == 0)); then
  echo "Please specify --domains/-d (or --csr/-c if you already have a CSR)" >&2; exit 1
fi
: "${PATHD:?lego stub: no --path}"
CERTS="$PATHD/certificates"; mkdir -p "$CERTS"
CA="$LEGO_STUB_CA"            # directory holding int.crt/int.key/ca.crt

san_of_csr() { openssl req -in "$1" -noout -text | grep -o 'DNS:[^,[:space:]]*' | sed 's/^DNS://'; }
sanitize()   { printf '%s' "${1//\*/_}"; }

if [[ -n $CSR ]]; then
  cn=$(openssl req -in "$CSR" -noout -subject | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p' | head -1)
  main="${cn:-$(san_of_csr "$CSR" | head -1)}"
  [[ -n $main ]] || { echo "lego stub: missing domain" >&2; exit 1; }
  stem=$(sanitize "$main")
  mapfile -t names < <(san_of_csr "$CSR")
  reqfile="$CSR"
else
  main="${DOMS[0]}"; stem=$(sanitize "$main")
  names=( "${DOMS[@]}" )
  case "$KEYTYPE" in
    ec256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CERTS/$stem.key" 2>/dev/null ;;
    ec384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$CERTS/$stem.key" 2>/dev/null ;;
    *)     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CERTS/$stem.key" 2>/dev/null ;;
  esac
  sans=""; for d in "${names[@]}"; do sans+="DNS:$d,"; done
  reqfile=$(mktemp)
  openssl req -new -key "$CERTS/$stem.key" -subj "/CN=$main" \
    -addext "subjectAltName=${sans%,}" -out "$reqfile" 2>/dev/null
fi

sans=""; for d in "${names[@]}"; do sans+="DNS:$d,"; done
ext=$(mktemp)
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "${sans%,}" > "$ext"
openssl x509 -req -in "$reqfile" -CA "$CA/int.crt" -CAkey "$CA/int.key" \
  -set_serial "$(date +%s)" -days "${LEGO_STUB_DAYS:-90}" -extfile "$ext" \
  -out "$CERTS/.leaf.$$" 2>/dev/null
cat "$CERTS/.leaf.$$" "$CA/int.crt" > "$CERTS/$stem.crt"
cp "$CA/int.crt" "$CERTS/$stem.issuer.crt"
printf '{"domain":"%s","certUrl":"stub"}\n' "$main" > "$CERTS/$stem.json"
rm -f "$CERTS/.leaf.$$" "$ext"
[[ -n $CSR ]] && rm -f "$CERTS/$stem.key" || rm -f "$reqfile"
echo "lego stub: $SUB ok ($stem, $( [[ -n $CSR ]] && echo from-csr || echo generated-key ))"
LEGO
chmod +x "$T/bin/lego"

# --------------------------------------------------- dig / nsupdate / knotc --
# Everything the preflight wants to see: a CNAME from the public resolver and an
# authoritative (aa) answer from "our" Knot.
cat > "$T/bin/dig" <<'DIG'
#!/usr/bin/env bash
args="$*"
if [[ $args == *CNAME* ]]; then
  name=$(printf '%s\n' "$@" | tail -1)
  base="${name#_acme-challenge.}"
  echo "${base}.acme.example.com."
  exit 0
fi
if [[ $args == *SOA* ]]; then
  if [[ $args == *+noall* ]]; then
    echo ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1"
    echo ";; flags: qr aa rd; QUERY: 1, ANSWER: 0"
    exit 0
  fi
  exit 0
fi
if [[ $args == *TXT* ]]; then exit 0; fi
exit 0
DIG
chmod +x "$T/bin/dig"
printf '#!/bin/sh\ncat >/dev/null\nexit 0\n' > "$T/bin/nsupdate"; chmod +x "$T/bin/nsupdate"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/knotc";   chmod +x "$T/bin/knotc"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/logger";  chmod +x "$T/bin/logger"

# --------------------------------------------------------------- ssh stub ----
# Stands in for sshd + the forced command: the last argument is what the client
# sent, which becomes SSH_ORIGINAL_COMMAND, and the hostid allowlist comes from
# $T/agent/allowed -- exactly the role authorized_keys plays in production.
# stdin is passed straight through, which is what makes `submit` testable.
cat > "$T/bin/ssh" <<SSHSTUB
#!/usr/bin/env bash
set -Eeuo pipefail
cmd=""
for a in "\$@"; do cmd="\$a"; done
export SSH_ORIGINAL_COMMAND="\$cmd"
export SSH_CONNECTION="10.0.0.9 1234 10.0.0.1 22"
export CERTPULL_PULL_DIR="$T/var/lib/certpull/pull"
export CERTPULL_HOSTS_DIR="$T/etc/certpull/hosts.d"
export CERTPULL_CSR_DIR="$T/var/lib/certpull/csr"
# shellcheck disable=SC2046
exec "\${CERTPULL_TEST_SHELL:-$REPO/server/certpull-pull-shell}" \$(cat "$T/agent/allowed")
SSHSTUB
chmod +x "$T/bin/ssh"

printf 'a-full c-csr\n' > "$T/agent/allowed"

# ------------------------------------------------------------- curl stub ----
# Stands in for the web server in front of WWW_DIR: maps the URL path onto the
# published tree, supports -I (the agent's "is a private key being served?"
# probe) and -o, and fails like curl -f does on a missing file.
cat > "$T/bin/curl" <<CURLSTUB
#!/usr/bin/env bash
set -uo pipefail
head_only=0; out=""; url=""
while (( \$# )); do
  case "\$1" in
    -I|--head) head_only=1; shift ;;
    -o) out="\$2"; shift 2 ;;
    -fsS|-fsSL|--proto|--tlsv1.2|--max-time|--connect-timeout|--retry|--retry-delay)
        case "\$1" in --proto|--max-time|--connect-timeout|--retry|--retry-delay) shift 2 ;; *) shift ;; esac ;;
    https://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
[[ -n \$url ]] || exit 2
rel="\${url#https://stub/certs/}"
[[ \$rel != "\$url" ]] || exit 6              # unknown host, like curl's 6
f="$T/var/lib/certpull/www/\$rel"
if [[ -f \$f ]]; then
  if (( head_only )); then exit 0; fi
  if [[ -n \$out ]]; then cat "\$f" > "\$out"; else cat "\$f"; fi
  exit 0
fi
exit 22                                        # curl -f on a 404
CURLSTUB
chmod +x "$T/bin/curl"

# ------------------------------------------------------------ server config --
cat > "$T/etc/certpull/certpull.conf" <<EOF
ACME_EMAIL="pki@example.com"
ACME_SERVER="https://stub.invalid/directory"
ACME_ZONE="acme.example.com"
ACME_NS_NAME="ns-certpull.example.com"
DNS_SERVER="127.0.0.1"
DNS_PORT="53"
TSIG_FILE="$T/etc/certpull/tsig.env"
RENEW_DAYS="15"
DEFAULT_KEY_TYPE="ec256"
PROPAGATION_WAIT="0"
DNS_RESOLVERS="8.8.8.8:53,9.9.9.9:53"
PROPAGATION_RNS="yes"
PURGE_STALE_TXT="no"
HOSTS_DIR="$T/etc/certpull/hosts.d"
LEGO_DIR="$T/var/lib/certpull/lego"
PULL_DIR="$T/var/lib/certpull/pull"
CSR_DIR="$T/var/lib/certpull/csr"
LOG_TAG="certpull-test"
EOF
cat > "$T/etc/certpull/tsig.env" <<'EOF'
TSIG_NAME="certpull."
TSIG_ALG="hmac-sha256."
TSIG_SECRET="dGVzdHNlY3JldA=="
EOF

# host A: the original behaviour, server-side key
cat > "$T/etc/certpull/hosts.d/a-full.conf" <<'EOF'
DOMAINS="a-full.example.com www.a-full.example.com"
KEY_TYPE=""
RENEW_DAYS=""
ENABLED="yes"
ACME_ZONE=""
CSR_MODE="no"
EOF

# host C: the new behaviour, key stays on the agent
cat > "$T/etc/certpull/hosts.d/c-csr.conf" <<'EOF'
DOMAINS="c-csr.example.com alt.c-csr.example.com"
KEY_TYPE=""
RENEW_DAYS=""
ENABLED="yes"
ACME_ZONE=""
CSR_MODE="yes"
EOF

# ------------------------------------------------------------- agent config --
mkdir -p "$T/agenthome/.config/certpull" "$T/agenthome/.ssh" "$T/agenthome/.cache/certpull"
touch "$T/agenthome/.ssh/id_ed25519"; chmod 600 "$T/agenthome/.ssh/id_ed25519"

mk_agent_conf() {            # $1 = name, $2 = hostid, $3 = CSR_MODE value
  cat > "$T/agenthome/.config/certpull/$1.conf" <<EOF
SERVER="certpull@stub"
SERVER_PORT="22"
HOSTID="$2"
SSH_KEY="$T/agenthome/.ssh/id_ed25519"
KNOWN_HOSTS="$T/agenthome/.ssh/known_hosts"
DEST="$T/agenthome/certs-$1"
DEST_MODE="0700"
FILE_STYLE="pem"
CERT_MODE="0644"
KEY_MODE="0600"
COMBINED="no"
EXPECT_DOMAINS=""
RELOAD_CMD=""
CSR_MODE="$3"
AGENT_KEY_TYPE="ec256"
EOF
}
mk_agent_conf full a-full ""
mk_agent_conf csr  c-csr  ""

echo "sandbox ready: $T"
