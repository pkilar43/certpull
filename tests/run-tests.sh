#!/usr/bin/env bash
# certpull test suite -- exercises both certificate modes end to end against
# stubs. It never contacts a real ACME server, never touches a real DNS zone,
# and writes nothing outside its own sandbox directory.
#
#   ./tests/run-tests.sh
#   T=/var/tmp/certpull-test ./tests/run-tests.sh      keep the sandbox to poke at
#   CERTPULL_OLD_REF=<git-ref> ./tests/run-tests.sh    also test a pre-CSR agent
#
# What it covers: full mode unchanged, the CSR-mode bootstrap, renewal, key
# rotation, what a malicious agent cannot ask for, a compromised server trying
# to push a foreign certificate, tampering with a published bundle, wildcard
# domains, DOMAINS changes, mode switches, and compatibility in both directions.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
export REPO="${REPO:-$(cd "$HERE/.." && pwd)}"
export T="${T:-${TMPDIR:-/tmp}/certpull-tests.$$}"
KEEP="${T_KEEP:-0}"
if [[ -z ${T_EXPLICIT:-} && -z ${T+x} ]]; then :; fi

for tool in openssl tar sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

bash "$HERE/lib/sandbox.sh" >/dev/null
export PATH="$T/bin:$PATH"
export LEGO_STUB_CA="$T/ca"
export CERTPULL_CONF="$T/etc/certpull/certpull.conf"

ISSUE="$REPO/server/certpull-issue"
HOST="$REPO/server/certpull-host"
STATUS="$REPO/server/certpull-status"
AGENT="$REPO/agent/certpull-agent"
PULL="$T/var/lib/certpull/pull"
CSRD="$T/var/lib/certpull/csr"

PASS=0; FAIL=0
hdr() { printf '\n\033[1m=== %s\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
no()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
chk() { if [[ $1 == 0 ]]; then ok "$2"; else no "$2"; fi; }

agent_run() {                # $1 = profile, rest = flags
  local p="$1"; shift
  HOME="$T/agenthome" XDG_CONFIG_HOME="$T/agenthome/.config" \
  CERTPULL_AGENT_CONF="$T/agenthome/.config/certpull/$p.conf" \
  TMPDIR="$T/tmp" "$AGENT" "$@"
}
mkdir -p "$T/tmp"

rewrite_meta() {             # $1 = meta.json, $2 = fingerprint, $3 = spki
  python3 -c '
import re,sys
p,fp,spki=sys.argv[1:4]
s=open(p).read()
s=re.sub(r"\"fingerprint_sha256\":\"[^\"]*\"","\"fingerprint_sha256\":\"%s\""%fp,s)
s=re.sub(r"\"spki_sha256\":\"[^\"]*\"","\"spki_sha256\":\"%s\""%spki,s)
open(p,"w").write(s)' "$1" "$2" "$3"
}

spki_key()  { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -hex | sed 's/.*= *//'; }
spki_cert() { openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex | sed 's/.*= *//'; }

# ===========================================================================
hdr "1. full mode (unchanged behaviour)"
"$ISSUE" a-full >/dev/null 2>&1; chk $? "certpull-issue a-full"
[[ -s $PULL/a-full/privkey.pem ]]; chk $? "the server publishes privkey.pem in full mode"

agent_run full >/dev/null 2>&1; chk $? "the agent installs it"
D="$T/agenthome/certs-full"
[[ -s $D/privkey.pem && -s $D/fullchain.pem ]]; chk $? "key + certificate landed in the destination"
[[ "$(spki_key "$D/privkey.pem")" == "$(spki_cert "$D/cert.pem")" ]]; chk $? "the installed key matches the certificate"

out=$(agent_run full 2>&1); echo "$out" | grep -q "up to date"; chk $? "the second run is a no-op"

# ===========================================================================
hdr "2. CSR mode: bootstrap"
out=$("$ISSUE" c-csr 2>&1); rc=$?
echo "$out" | grep -q "waiting for the agent to submit a CSR"; chk $? "issue says it is waiting for a CSR"
[[ $rc == 0 ]]; chk $? "a host without a CSR does NOT fail the run (rc=$rc)"
[[ ! -d $PULL/c-csr ]]; chk $? "nothing published yet"

out=$("$STATUS" 2>&1); echo "$out" | grep -qE 'c-csr +csr +NOCSR'; chk $? "certpull-status shows mode=csr state=NOCSR"

out=$(agent_run csr 2>&1); rc=$?
echo "$out" | grep -q "generated a new ec256 private key"; chk $? "the agent generated its own key"
echo "$out" | grep -q "accepted CSR for c-csr"; chk $? "the server accepted the CSR"
[[ $rc == 0 ]]; chk $? "the agent exits 0 while waiting for the first certificate"
[[ -s $CSRD/c-csr.csr ]]; chk $? "the CSR is stored on the server"
AD="$T/agenthome/certs-csr"
[[ -s $AD/.pending.privkey.pem ]]; chk $? "the key is PENDING, not yet active"
[[ ! -e $AD/privkey.pem ]]; chk $? "no active key before a matching certificate exists"
AGENT_SPKI=$(spki_key "$AD/.pending.privkey.pem")

out=$("$HOST" csr c-csr 2>&1); echo "$out" | grep -q "ok   spki=$AGENT_SPKI"; chk $? "certpull-host csr reports the agent's key"

hdr "3. CSR mode: signing and installation"
out=$("$ISSUE" c-csr 2>&1); rc=$?
echo "$out" | grep -q "signing the agent's CSR"; chk $? "issue signs the CSR"
[[ $rc == 0 ]]; chk $? "issue succeeded"
[[ ! -e $PULL/c-csr/privkey.pem ]]; chk $? "NO private key is published in CSR mode"
[[ -s $PULL/c-csr/cert.pem && -s $PULL/c-csr/fullchain.pem ]]; chk $? "the certificate is published"
grep -q '"mode":"csr"' "$PULL/c-csr/meta.json"; chk $? "meta.json says mode=csr"
[[ "$(spki_cert "$PULL/c-csr/cert.pem")" == "$AGENT_SPKI" ]]; chk $? "the issued certificate belongs to the agent's key"
[[ ! -e $T/var/lib/certpull/lego/certificates/c-csr.example.com.key ]]; chk $? "lego left no private key on the server"
grep -q 'privkey' "$PULL/c-csr/SHA256SUMS"; r=$?; [[ $r != 0 ]]; chk $? "SHA256SUMS lists no privkey"

out=$(agent_run csr 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "the agent installs the certificate"
echo "$out" | grep -q "the new private key is now the active one"; chk $? "the pending key was promoted"
[[ -s $AD/privkey.pem && ! -e $AD/.pending.privkey.pem ]]; chk $? "the key is active and the pending copy is gone"
[[ "$(spki_key "$AD/privkey.pem")" == "$AGENT_SPKI" ]]; chk $? "the active key is the one the agent generated itself"
[[ "$(spki_key "$AD/privkey.pem")" == "$(spki_cert "$AD/cert.pem")" ]]; chk $? "the installed key matches the installed certificate"

out=$(agent_run csr 2>&1); echo "$out" | grep -q "up to date"; chk $? "the next run is a no-op (one extra verb, no extra work)"

out=$(agent_run csr --check 2>&1)
echo "$out" | grep -q "mode:      csr"; chk $? "--check shows the mode"
echo "$out" | grep -q "state:     up to date"; chk $? "--check shows up to date"
[[ -s $AD/privkey.pem ]]; chk $? "--check changed nothing"

hdr "4. CSR mode: renewal keeps the same key"
OLD_FP=$(openssl x509 -in "$AD/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
"$ISSUE" --force c-csr >/dev/null 2>&1; chk $? "forced renewal"
agent_run csr >/dev/null 2>&1; chk $? "the agent picks the renewal up"
NEW_FP=$(openssl x509 -in "$AD/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
[[ -n $NEW_FP && $OLD_FP != "$NEW_FP" ]]; chk $? "the certificate really changed"
[[ "$(spki_key "$AD/privkey.pem")" == "$AGENT_SPKI" ]]; chk $? "the private key did NOT change on renewal"

hdr "5. CSR mode: key rotation"
out=$(agent_run csr --rotate-key 2>&1)
echo "$out" | grep -q "generated a new ec256 private key"; chk $? "--rotate-key made a new key"
NEW_SPKI=$(spki_key "$AD/.pending.privkey.pem")
[[ -n $NEW_SPKI && $NEW_SPKI != "$AGENT_SPKI" ]]; chk $? "the new key is different"
[[ "$(spki_key "$AD/privkey.pem")" == "$AGENT_SPKI" ]]; chk $? "the OLD key is still the active one"
[[ "$(spki_key "$AD/privkey.pem")" == "$(spki_cert "$AD/cert.pem")" ]]; chk $? "the service still has a matching pair"
echo "$out" | grep -q "accepted CSR"; chk $? "a CSR for the new key was submitted"

out=$(agent_run csr 2>&1)
echo "$out" | grep -q "accepted CSR"; chk $? "it keeps resubmitting while unsigned (self-healing)"
[[ "$(spki_key "$AD/privkey.pem")" == "$AGENT_SPKI" ]]; chk $? "still no premature promotion"

"$ISSUE" --force c-csr >/dev/null 2>&1; chk $? "the server signs the rotated CSR"
[[ "$(spki_cert "$PULL/c-csr/cert.pem")" == "$NEW_SPKI" ]]; chk $? "the new certificate is for the new key"
agent_run csr >/dev/null 2>&1; chk $? "the agent installs it"
[[ "$(spki_key "$AD/privkey.pem")" == "$NEW_SPKI" ]]; chk $? "the rotated key is now active"
[[ ! -e $AD/.pending.privkey.pem ]]; chk $? "no pending key left over"
AGENT_SPKI="$NEW_SPKI"

# ===========================================================================
hdr "6. authorisation: what a malicious agent cannot do"
K="$AD/privkey.pem"

try_submit() {               # $1 = subject, $2 = SANs, $3 = hostid
  local c; c=$(mktemp)
  openssl req -new -key "$K" -subj "$1" -addext "subjectAltName=$2" -out "$c" 2>/dev/null
  SSH_ORIGINAL_COMMAND="submit $3" SSH_CONNECTION="10.0.0.9 1 10.0.0.1 22" \
  CERTPULL_PULL_DIR="$PULL" CERTPULL_HOSTS_DIR="$T/etc/certpull/hosts.d" CERTPULL_CSR_DIR="$CSRD" \
    "$REPO/server/certpull-pull-shell" a-full c-csr < "$c" 2>&1
  local rc=$?; rm -f "$c"; return $rc
}

out=$(try_submit "/CN=c-csr.example.com" "DNS:c-csr.example.com,DNS:alt.c-csr.example.com,DNS:evil.example.com" c-csr)
[[ $? != 0 ]] && echo "$out" | grep -q "not the ones authorised"; chk $? "an extra SAN is rejected"

out=$(try_submit "/CN=c-csr.example.com" "DNS:c-csr.example.com" c-csr)
[[ $? != 0 ]] && echo "$out" | grep -q "not the ones authorised"; chk $? "a missing SAN is rejected"

out=$(try_submit "/CN=evil.example.com" "DNS:evil.example.com" c-csr)
[[ $? != 0 ]] && echo "$out" | grep -q "not the ones authorised"; chk $? "a foreign name is rejected"

out=$(try_submit "/CN=a-full.example.com" "DNS:a-full.example.com,DNS:www.a-full.example.com" a-full)
[[ $? != 0 ]] && echo "$out" | grep -q "not in CSR mode"; chk $? "submitting to a full-mode host is rejected"

out=$(SSH_ORIGINAL_COMMAND="submit somebody-else" CERTPULL_PULL_DIR="$PULL" \
      CERTPULL_HOSTS_DIR="$T/etc/certpull/hosts.d" CERTPULL_CSR_DIR="$CSRD" \
      "$REPO/server/certpull-pull-shell" a-full c-csr </dev/null 2>&1)
[[ $? != 0 ]] && echo "$out" | grep -q "no access to somebody-else"; chk $? "submitting for a hostid outside the forced command is rejected"

WK=$(mktemp); openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$WK" 2>/dev/null
WC=$(mktemp)
openssl req -new -key "$WK" -subj "/CN=c-csr.example.com" \
  -addext "subjectAltName=DNS:c-csr.example.com,DNS:alt.c-csr.example.com" -out "$WC" 2>/dev/null
out=$(SSH_ORIGINAL_COMMAND="submit c-csr" CERTPULL_PULL_DIR="$PULL" \
      CERTPULL_HOSTS_DIR="$T/etc/certpull/hosts.d" CERTPULL_CSR_DIR="$CSRD" \
      "$REPO/server/certpull-pull-shell" a-full c-csr < "$WC" 2>&1)
[[ $? != 0 ]] && echo "$out" | grep -q "too short"; chk $? "an RSA-1024 key is rejected"
rm -f "$WK" "$WC"

out=$(SSH_ORIGINAL_COMMAND="rm -rf /" CERTPULL_PULL_DIR="$PULL" \
      CERTPULL_HOSTS_DIR="$T/etc/certpull/hosts.d" CERTPULL_CSR_DIR="$CSRD" \
      "$REPO/server/certpull-pull-shell" a-full c-csr </dev/null 2>&1)
[[ $? != 0 ]] && echo "$out" | grep -qE "bad hostid|command not allowed"; chk $? "an arbitrary command is still refused"

[[ -s $CSRD/c-csr.csr ]] && [[ "$(openssl req -in "$CSRD/c-csr.csr" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex | sed 's/.*= *//')" == "$AGENT_SPKI" ]]
chk $? "none of the rejected submissions overwrote the good CSR"

hdr "7. the server cannot push a certificate for a key the agent does not hold"
FOREIGN=$(mktemp); openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$FOREIGN" 2>/dev/null
FCSR=$(mktemp)
openssl req -new -key "$FOREIGN" -subj "/CN=c-csr.example.com" \
  -addext "subjectAltName=DNS:c-csr.example.com,DNS:alt.c-csr.example.com" -out "$FCSR" 2>/dev/null
cp "$FCSR" "$CSRD/c-csr.csr"          # as if the server had been compromised
"$ISSUE" --force c-csr >/dev/null 2>&1; chk $? "the server publishes a certificate for a foreign key"
out=$(agent_run csr 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "the agent does not treat it as a hard failure"
echo "$out" | grep -q "accepted CSR"; chk $? "instead it resubmits its own CSR"
[[ "$(spki_key "$AD/privkey.pem")" == "$AGENT_SPKI" ]]; chk $? "the local key is untouched"
[[ "$(spki_cert "$AD/cert.pem")" == "$AGENT_SPKI" ]]; chk $? "the foreign certificate was NOT installed"
rm -f "$FOREIGN" "$FCSR"
"$ISSUE" --force c-csr >/dev/null 2>&1   # restore a sane state
agent_run csr >/dev/null 2>&1

hdr "8. tampering with the published bundle"
# Re-sign the agent's own names onto a different key and swap the files in,
# keeping SHA256SUMS and meta.json consistent -- i.e. the strongest a
# compromised server could do without the agent's key.
EK=$(mktemp); openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$EK" 2>/dev/null
ECSR=$(mktemp); EEXT=$(mktemp)
openssl req -new -key "$EK" -subj "/CN=c-csr.example.com" -out "$ECSR" 2>/dev/null
printf 'subjectAltName=DNS:c-csr.example.com,DNS:alt.c-csr.example.com\n' > "$EEXT"
openssl x509 -req -in "$ECSR" -CA "$T/ca/int.crt" -CAkey "$T/ca/int.key" -set_serial 999 \
  -days 90 -extfile "$EEXT" -out "$PULL/c-csr/.evil" 2>/dev/null
cat "$PULL/c-csr/.evil" "$T/ca/int.crt" > "$PULL/c-csr/fullchain.pem"
cp "$PULL/c-csr/.evil" "$PULL/c-csr/cert.pem"; rm -f "$PULL/c-csr/.evil"
EFP=$(openssl x509 -in "$PULL/c-csr/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
ESPKI=$(spki_cert "$PULL/c-csr/cert.pem")
python3 - "$PULL/c-csr/meta.json" "$EFP" "$ESPKI" <<'PY'
import re,sys
p,fp,spki=sys.argv[1:4]
s=open(p).read()
s=re.sub(r'"fingerprint_sha256":"[^"]*"','"fingerprint_sha256":"%s"'%fp,s)
s=re.sub(r'"spki_sha256":"[^"]*"','"spki_sha256":"%s"'%spki,s)
open(p,'w').write(s)
PY
( cd "$PULL/c-csr" && sha256sum cert.pem chain.pem fullchain.pem meta.json > SHA256SUMS )
BEFORE=$(spki_cert "$AD/cert.pem")
out=$(agent_run csr 2>&1); rc=$?
echo "$out" | grep -q "accepted CSR"; chk $? "the agent sees a certificate for a key it does not hold and resubmits"
[[ "$(spki_cert "$AD/cert.pem")" == "$BEFORE" ]]; chk $? "the tampered certificate was not installed"
[[ "$(spki_key "$AD/privkey.pem")" == "$(spki_cert "$AD/cert.pem")" ]]; chk $? "the destination is still internally consistent"
rm -f "$EK" "$ECSR" "$EEXT"

# ===========================================================================
hdr "9. compatibility in both directions"
# restore a good csr-mode publication
"$ISSUE" --force c-csr >/dev/null 2>&1; agent_run csr >/dev/null 2>&1

# An "old server" is the current pull-shell with the two new verbs taken away.
# That is what the agent's fallback path has to cope with, and it needs no git.
OLD_SHELL="$T/bin/old-pull-shell"
cat > "$OLD_SHELL" <<OLDEOF
#!/usr/bin/env bash
read -r v _ <<<"\${SSH_ORIGINAL_COMMAND:-fetch}"
case "\$v" in
  config|submit) echo "certpull: command not allowed: \$v (allowed: list ping meta sums fetch)" >&2; exit 1 ;;
esac
exec "$REPO/server/certpull-pull-shell" "\$@"
OLDEOF
chmod +x "$OLD_SHELL"

out=$(CERTPULL_TEST_SHELL="$OLD_SHELL" agent_run full --force 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "a NEW agent still works against an OLD server in full mode"
out=$(CERTPULL_TEST_SHELL="$OLD_SHELL" agent_run full 2>&1)
echo "$out" | grep -q "up to date"; chk $? "and its steady state needs no new verb"
out=$(CERTPULL_TEST_SHELL="$OLD_SHELL" bash -c "sed -i 's|^CSR_MODE=.*|CSR_MODE=\"yes\"|' '$T/agenthome/.config/certpull/full.conf'; true"; \
      CERTPULL_TEST_SHELL="$OLD_SHELL" agent_run full 2>&1); rc=$?
[[ $rc != 0 ]] && echo "$out" | grep -q "too old for CSR mode"; chk $? "an agent asked for CSR mode against an old server says so plainly"
sed -i 's|^CSR_MODE=.*|CSR_MODE=""|' "$T/agenthome/.config/certpull/full.conf"

# The other direction needs the actual previous agent, so it is opt-in.
if [[ -n ${CERTPULL_OLD_REF:-} ]] && OLD_AGENT=$(mktemp) \
   && git -C "$REPO" show "$CERTPULL_OLD_REF:agent/certpull-agent" > "$OLD_AGENT" 2>/dev/null \
   && [[ -s $OLD_AGENT ]]; then
  out=$(HOME="$T/agenthome" XDG_CONFIG_HOME="$T/agenthome/.config" \
        CERTPULL_AGENT_CONF="$T/agenthome/.config/certpull/csr.conf" TMPDIR="$T/tmp" \
        bash "$OLD_AGENT" --force 2>&1); rc=$?
  [[ $rc != 0 ]]; chk $? "an OLD agent ($CERTPULL_OLD_REF) fails against a csr-mode host instead of installing something wrong"
  echo "$out" | grep -q "privkey.pem is missing"; chk $? "and it fails closed, with a clear reason"
  rm -f "$OLD_AGENT"
else
  printf '  \033[33mSKIP\033[0m old agent vs csr-mode host (set CERTPULL_OLD_REF=<git-ref> to run it)\n'
fi

hdr "10. mode assertion"
sed -i 's|^CSR_MODE=.*|CSR_MODE="yes"|' "$T/agenthome/.config/certpull/full.conf"
out=$(agent_run full 2>&1); rc=$?
[[ $rc != 0 ]] && echo "$out" | grep -q "mode mismatch"; chk $? "CSR_MODE=yes against a full-mode host is an error"
sed -i 's|^CSR_MODE=.*|CSR_MODE=""|' "$T/agenthome/.config/certpull/full.conf"

sed -i 's|^CSR_MODE=.*|CSR_MODE="yes"|' "$T/agenthome/.config/certpull/csr.conf"
out=$(agent_run csr 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "CSR_MODE=yes against a csr-mode host is fine"
sed -i 's|^CSR_MODE=.*|CSR_MODE=""|' "$T/agenthome/.config/certpull/csr.conf"

hdr "11. switching an existing full-mode host to CSR mode"
SW_BEFORE=$(spki_key "$T/agenthome/certs-full/privkey.pem")
sed -i 's|^CSR_MODE=.*|CSR_MODE="yes"|' "$T/etc/certpull/hosts.d/a-full.conf"
out=$("$ISSUE" a-full 2>&1); echo "$out" | grep -q "waiting for the agent"; chk $? "the server now waits for a CSR"
out=$(agent_run full 2>&1)
echo "$out" | grep -q "the old key came from the server, generating a fresh one"; chk $? "the agent refuses to reuse the key the server had"
SW_PENDING=$(spki_key "$T/agenthome/certs-full/.pending.privkey.pem")
[[ -n $SW_PENDING && $SW_PENDING != "$SW_BEFORE" ]]; chk $? "the new key is genuinely new"
[[ "$(spki_key "$T/agenthome/certs-full/privkey.pem")" == "$SW_BEFORE" ]]; chk $? "the service keeps the old pair until the new cert arrives"
"$ISSUE" a-full >/dev/null 2>&1; chk $? "the server signs the new CSR"
agent_run full >/dev/null 2>&1; chk $? "the agent completes the switch"
[[ "$(spki_key "$T/agenthome/certs-full/privkey.pem")" == "$SW_PENDING" ]]; chk $? "the agent's own key is now in use"
[[ ! -e $PULL/a-full/privkey.pem ]]; chk $? "the server no longer publishes a private key for this host"

hdr "12. whole-fleet run"
out=$("$ISSUE" 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "a run over every host succeeds"
echo "$out" | grep -q "summary:"; chk $? "it prints a summary"
"$HOST" list 2>&1 | sed 's/^/    /'
"$STATUS" 2>&1 | sed 's/^/    /'

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL == 0 ]]

# ===========================================================================
hdr "13. edge cases"

# --- a wildcard certificate in CSR mode ---
cat > "$T/etc/certpull/hosts.d/d-wild.conf" <<'WC'
DOMAINS="*.lan.example.com lan.example.com"
KEY_TYPE=""
RENEW_DAYS=""
ENABLED="yes"
ACME_ZONE=""
CSR_MODE="yes"
WC
printf 'a-full c-csr d-wild\n' > "$T/agent/allowed"
mk_wild() {
  cat > "$T/agenthome/.config/certpull/wild.conf" <<EOF
SERVER="certpull@stub"
HOSTID="d-wild"
SSH_KEY="$T/agenthome/.ssh/id_ed25519"
KNOWN_HOSTS="$T/agenthome/.ssh/known_hosts"
DEST="$T/agenthome/certs-wild"
DEST_MODE="0700"
FILE_STYLE="pem"
CSR_MODE=""
AGENT_KEY_TYPE="ec256"
RELOAD_CMD=""
EOF
}
mk_wild
out=$(agent_run wild 2>&1); echo "$out" | grep -q "accepted CSR for d-wild"; chk $? "a wildcard CSR is accepted"
"$ISSUE" d-wild >/dev/null 2>&1; chk $? "the wildcard certificate is issued"
[[ -s $PULL/d-wild/cert.pem ]]; chk $? "and published"
out=$(agent_run wild 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "the agent installs the wildcard certificate (rc=$rc)"
WD="$T/agenthome/certs-wild"
[[ -s $WD/privkey.pem ]] && [[ "$(spki_key "$WD/privkey.pem")" == "$(spki_cert "$WD/cert.pem")" ]]
chk $? "wildcard: key and certificate match"
openssl x509 -in "$WD/cert.pem" -noout -text | grep -q 'DNS:\*\.lan\.example\.com'; chk $? "the SAN really is a wildcard"

# --- a pure wildcard, with no bare apex name alongside it ---
cat > "$T/etc/certpull/hosts.d/e-pure.conf" <<'WC'
DOMAINS="*.pure.example.com"
KEY_TYPE=""
RENEW_DAYS=""
ENABLED="yes"
ACME_ZONE=""
CSR_MODE="yes"
WC
printf 'a-full c-csr d-wild e-pure\n' > "$T/agent/allowed"
sed -e 's/d-wild/e-pure/' -e 's/certs-wild/certs-pure/' "$T/agenthome/.config/certpull/wild.conf" \
  > "$T/agenthome/.config/certpull/pure.conf"
agent_run pure >/dev/null 2>&1
"$ISSUE" e-pure >/dev/null 2>&1
out=$(agent_run pure 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "a pure-wildcard certificate installs (rc=$rc)"
[[ -s $T/agenthome/certs-pure/fullchain.pem ]]; chk $? "pure wildcard landed in the destination"

# --- preflight on a CSR-mode host with no CSR yet ---
cat > "$T/etc/certpull/hosts.d/f-nocsr.conf" <<'WC'
DOMAINS="f.example.com"
ENABLED="yes"
CSR_MODE="yes"
WC
out=$("$ISSUE" --preflight f-nocsr 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "--preflight works before any CSR exists (rc=$rc)"
echo "$out" | grep -q "preflight OK"; chk $? "and it really checked the DNS delegation"
out=$("$ISSUE" --dry-run f-nocsr 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "--dry-run on a host without a CSR is not an error"
rm -f "$T/etc/certpull/hosts.d/f-nocsr.conf"

# --- a stale CSR after DOMAINS changed on the server ---
sed -i 's|^DOMAINS=.*|DOMAINS="c-csr.example.com alt.c-csr.example.com extra.c-csr.example.com"|' \
  "$T/etc/certpull/hosts.d/c-csr.conf"
out=$("$ISSUE" c-csr 2>&1); rc=$?
[[ $rc != 0 ]]; chk $? "a CSR that no longer covers DOMAINS fails the host"
echo "$out" | grep -q "not valid for the current DOMAINS"; chk $? "and says exactly that"
echo "$out" | grep -q "certpull-agent --submit"; chk $? "and says what to do about it"
out=$("$HOST" csr c-csr 2>&1); echo "$out" | grep -q "STALE/INVALID"; chk $? "certpull-host csr flags it too"
out=$(agent_run csr 2>&1); chk $? "the agent resubmits for the new domain set"
"$ISSUE" c-csr >/dev/null 2>&1; chk $? "and then it issues"
agent_run csr >/dev/null 2>&1
openssl x509 -in "$T/agenthome/certs-csr/cert.pem" -noout -text \
  | grep -q 'DNS:extra\.c-csr\.example\.com'; chk $? "the new name is in the installed certificate"


hdr "14. wildcard domains in FULL mode (regression)"
cat > "$T/etc/certpull/hosts.d/g-wildfull.conf" <<'WC'
DOMAINS="*.wf.example.com wf.example.com"
KEY_TYPE=""
RENEW_DAYS=""
ENABLED="yes"
ACME_ZONE=""
CSR_MODE="no"
WC
out=$("$ISSUE" g-wildfull 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "a wildcard host issues in full mode (rc=$rc)"
openssl x509 -in "$PULL/g-wildfull/cert.pem" -noout -text 2>/dev/null \
  | grep -q 'DNS:\*\.wf\.example\.com'; chk $? "the wildcard name survived into the certificate"
openssl x509 -in "$PULL/g-wildfull/cert.pem" -noout -text 2>/dev/null \
  | grep -q 'DNS:wf\.example\.com'; chk $? "and so did the bare name"

cat > "$T/etc/certpull/hosts.d/h-purefull.conf" <<'WC'
DOMAINS="*.pf.example.com"
ENABLED="yes"
CSR_MODE="no"
WC
out=$("$ISSUE" h-purefull 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "a PURE wildcard host issues in full mode (rc=$rc)"
[[ -s $PULL/h-purefull/cert.pem ]]; chk $? "and gets published"

printf 'a-full c-csr d-wild e-pure h-purefull\n' > "$T/agent/allowed"
cat > "$T/agenthome/.config/certpull/purefull.conf" <<EOF
SERVER="certpull@stub"
HOSTID="h-purefull"
SSH_KEY="$T/agenthome/.ssh/id_ed25519"
KNOWN_HOSTS="$T/agenthome/.ssh/known_hosts"
DEST="$T/agenthome/certs-purefull"
DEST_MODE="0700"
FILE_STYLE="pem"
RELOAD_CMD=""
EOF
out=$(agent_run purefull 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "the agent installs a pure-wildcard certificate (rc=$rc)"
[[ -s $T/agenthome/certs-purefull/privkey.pem ]]; chk $? "wildcard full-mode bundle landed complete"


hdr "15. a DOMAINS change in FULL mode (regression)"
BEFORE_FP=$(openssl x509 -in "$PULL/g-wildfull/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
sed -i 's|^DOMAINS=.*|DOMAINS="*.wf.example.com wf.example.com added.wf.example.com"|' \
  "$T/etc/certpull/hosts.d/g-wildfull.conf"
out=$("$ISSUE" g-wildfull 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "issue succeeds after a DOMAINS change (rc=$rc)"
echo "$out" | grep -q "DOMAINS changed -> re-issuing"; chk $? "it noticed the change instead of waiting for renewal"
AFTER_FP=$(openssl x509 -in "$PULL/g-wildfull/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
[[ -n $AFTER_FP && $AFTER_FP != "$BEFORE_FP" ]]; chk $? "a new certificate was published"
openssl x509 -in "$PULL/g-wildfull/cert.pem" -noout -text | grep -q 'DNS:added\.wf\.example\.com'
chk $? "the added name is in it"
out=$("$ISSUE" g-wildfull 2>&1)
echo "$out" | grep -q "DOMAINS changed"; r=$?; [[ $r != 0 ]]; chk $? "and it does not keep re-issuing afterwards"

hdr "16. install-server.sh --update --dry-run"
grep -q 'certpull-csrlib.sh' "$REPO/server/install-server.sh"; chk $? "the installer ships certpull-csrlib.sh"
grep -q 'install_csr_dir' "$REPO/server/install-server.sh"; chk $? "the installer creates the CSR directory"
safe_seed_has() {            # the array spans several lines, so flatten it first
  sed -n '/^SAFE_SEED=(/,/)/p' "$REPO/server/install-server.sh" | tr -s ' \n' ' ' | grep -qw "$1"
}
safe_seed_has CSR_DIR;      chk $? "CSR_DIR is seeded into an existing config"
safe_seed_has WWW_DIR;      chk $? "so is WWW_DIR"
safe_seed_has WWW_BASE_URL; chk $? "and WWW_BASE_URL"
grep -q 'certpull-wwwlib.sh' "$REPO/server/install-server.sh"; chk $? "the installer ships certpull-wwwlib.sh"
grep -q '^CSR_DIR=' "$REPO/server/certpull.conf.example"; chk $? "and exists in the template"
grep -q '^CSR_MODE=' "$REPO/server/hosts.d/example.conf"; chk $? "CSR_MODE is documented in the host template"
# every sed pattern in the installers must match a line that really exists
for pat in ACME_EMAIL ACME_ZONE ACME_NS_NAME; do
  grep -qE "^${pat}=" "$REPO/server/certpull.conf.example"; chk $? "install-server sed target ${pat} exists in the template"
done
for pat in SERVER SERVER_PORT HOSTID CSR_MODE; do
  grep -qE "^${pat}=" "$REPO/agent/agent.conf.example"; chk $? "install-agent sed target ${pat} exists in agent.conf.example"
  grep -qE "^${pat}=" "$REPO/agent/agent.conf.user.example"; chk $? "install-agent sed target ${pat} exists in agent.conf.user.example"
done

hdr "17. firewall plan (install-server.sh --show-firewall-plan)"
# A machine that also serves HTTPS, has a loopback-only database, and binds DNS
# on both address families. Nothing here needs root and nothing is changed.
cat > "$T/bin/ss" <<'SSEOF'
#!/bin/sh
case "$*" in
  *-tlnH*) printf 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 511 *:443 *:*\nLISTEN 0 511 *:80 *:*\nLISTEN 0 4096 127.0.0.53%%lo:53 0.0.0.0:*\nLISTEN 0 70 127.0.0.1:3306 0.0.0.0:*\nLISTEN 0 4096 [::]:53 [::]:*\n' ;;
  *-ulnH*) printf 'UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\nUNCONN 0 0 127.0.0.53%%lo:53 0.0.0.0:*\n' ;;
esac
SSEOF
chmod +x "$T/bin/ss"

plan=$("$REPO/server/install-server.sh" --show-firewall-plan 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "--show-firewall-plan runs without root and exits 0"
echo "$plan" | grep -q 'ufw allow 443/tcp'; chk $? "a listening HTTPS port is in the plan"
echo "$plan" | grep -q 'ufw allow 80/tcp';  chk $? "so is HTTP"
echo "$plan" | grep -q 'ufw allow 22/tcp';  chk $? "certpull's own SSH port is there"
echo "$plan" | grep -q 'ufw allow 53/tcp';  chk $? "and DNS tcp"
echo "$plan" | grep -q 'ufw allow 53/udp';  chk $? "and DNS udp"
echo "$plan" | grep -q '3306'; r=$?; [[ $r != 0 ]]; chk $? "a loopback-only port is NOT opened"
[[ $(echo "$plan" | grep -c 'ufw allow 53/tcp') == 1 ]]; chk $? "0.0.0.0 and [::] on the same port are not duplicated"
[[ $(echo "$plan" | grep -c 'ufw allow') == 5 ]]; chk $? "exactly the five expected rules"

# Order matters for readability, and comm needs a different sort than display.
[[ $(echo "$plan" | sed -n 's/^  ufw allow //p' | tr '\n' ' ') == "22/tcp 53/tcp 53/udp 80/tcp 443/tcp " ]]
chk $? "the plan is sorted numerically by port"

# No ss at all (a container, a stripped image): fall back to certpull's ports.
plan=$(PATH="/usr/bin:/bin" "$REPO/server/install-server.sh" --show-firewall-plan 2>&1)
echo "$plan" | grep -q '(nothing else)'; chk $? "without ss it detects nothing instead of guessing"
[[ $(echo "$plan" | grep -c 'ufw allow') == 3 ]]; chk $? "and still plans certpull's own three ports"

grep -q -- '--no-ufw' "$REPO/server/install-server.sh"; chk $? "--no-ufw exists"
grep -q 'was_active' "$REPO/server/install-server.sh"; chk $? "an already-active ufw is not re-enabled"
rm -f "$T/bin/ss"

hdr "18. publishing public bundles over HTTPS"
WWW="$T/var/lib/certpull/www"

# Off by default: nothing above this point configured WWW_BASE_URL, and nothing
# should have been published.
[[ ! -d $WWW ]] || [[ -z $(ls -A "$WWW" 2>/dev/null) ]]; chk $? "HTTPS publishing is off until WWW_BASE_URL is set"

echo 'WWW_BASE_URL="https://stub/certs"' >> "$T/etc/certpull/certpull.conf"
echo "WWW_DIR=\"$WWW\""                  >> "$T/etc/certpull/certpull.conf"

# A brand new host, created the way an operator would, so it gets a token.
out=$("$HOST" add --csr h-https h.example.com alt.h.example.com 2>&1); chk $? "certpull-host add --csr h-https"
echo "$out" | grep -q 'install-agent.sh --https'; chk $? "add tells you the HTTPS one-liner"
tok=$(sed -n 's/^WWW_TOKEN="\(.*\)"/\1/p' "$T/etc/certpull/hosts.d/h-https.conf")
[[ ${#tok} == 32 ]]; chk $? "a 128-bit path token was generated (${#tok} hex chars)"
URL=$("$HOST" url h-https); chk $? "certpull-host url prints the URL"
[[ $URL == "https://stub/certs/h-https-$tok" ]]; chk $? "the URL is <base>/<hostid>-<token>"
[[ -s $WWW/h-https-$tok/config.json ]]; chk $? "config.json exists before anything is issued"
grep -q '"mode":"csr"' "$WWW/h-https-$tok/config.json"; chk $? "and says mode=csr"
grep -q 'alt.h.example.com' "$WWW/h-https-$tok/config.json"; chk $? "and carries the authorised domains"

# The invariant: a full-mode host must never appear here.
"$ISSUE" --force a-full >/dev/null 2>&1
[[ -z $(find "$WWW" -maxdepth 1 -name 'a-full-*' 2>/dev/null) ]]; chk $? "a FULL-mode host is never published over HTTPS"
[[ -z $(find "$WWW" -type f -name 'privkey*' 2>/dev/null) ]]; chk $? "no privkey.pem anywhere under WWW_DIR"

hdr "19. the agent over HTTPS, end to end"
cat > "$T/agenthome/.config/certpull/https.conf" <<AGENTEOF
HOSTID="h-https"
TRANSPORT="https"
CERT_URL="$URL"
DEST="$T/agenthome/certs-https"
DEST_MODE="0700"
FILE_STYLE="pem"
CSR_MODE="yes"
AGENT_KEY_TYPE="ec256"
RELOAD_CMD=""
AGENTEOF

out=$(agent_run https 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "the first run succeeds without any SSH key (rc=$rc)"
echo "$out" | grep -q 'generated a new ec256 private key'; chk $? "it generated its own key"
echo "$out" | grep -q 'has no way to send one'; chk $? "and says the endpoint is read-only"
echo "$out" | grep -q 'certpull-host csr-import'; chk $? "with the exact enrolment commands"
HD="$T/agenthome/certs-https"
[[ -s $HD/.pending.privkey.pem && ! -e $HD/privkey.pem ]]; chk $? "the key is pending, nothing installed"
HSPKI=$(spki_key "$HD/.pending.privkey.pem")

out=$(agent_run https --check 2>&1)
echo "$out" | grep -q 'transport: https'; chk $? "--check names the transport"
echo "$out" | grep -q 'NEEDS ENROLMENT'; chk $? "--check says enrolment is needed"

agent_run https --print-csr > "$T/h-https.csr" 2>/dev/null; chk $? "--print-csr writes a CSR"
openssl req -in "$T/h-https.csr" -noout -verify >/dev/null 2>&1; chk $? "it is a valid CSR"
csrspki=$(openssl req -in "$T/h-https.csr" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex | sed 's/.*= *//')
[[ $csrspki == "$HSPKI" ]]; chk $? "for the key this machine holds"

out=$("$HOST" csr-import h-https "$T/h-https.csr" 2>&1); chk $? "csr-import accepts it"
echo "$out" | grep -q "$HSPKI"; chk $? "and reports the same SPKI"

out=$("$ISSUE" h-https 2>&1); chk $? "certpull-issue signs it"
echo "$out" | grep -q 'also published over HTTPS'; chk $? "and says it published over HTTPS"
[[ -s $WWW/h-https-$tok/fullchain.pem ]]; chk $? "fullchain.pem is on the endpoint"
[[ -s $WWW/h-https-$tok/SHA256SUMS ]]; chk $? "so is SHA256SUMS"
[[ ! -e $WWW/h-https-$tok/privkey.pem ]]; chk $? "and no private key"
[[ -s $WWW/h-https-$tok/config.json ]]; chk $? "config.json survived the atomic swap"

out=$(agent_run https 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "the agent installs over HTTPS (rc=$rc)"
echo "$out" | grep -q 'over https'; chk $? "and says which transport it used"
[[ -s $HD/privkey.pem && ! -e $HD/.pending.privkey.pem ]]; chk $? "the pending key was promoted"
[[ "$(spki_key "$HD/privkey.pem")" == "$HSPKI" ]]; chk $? "the active key is the one generated here"
[[ "$(spki_key "$HD/privkey.pem")" == "$(spki_cert "$HD/cert.pem")" ]]; chk $? "key and certificate match"
out=$(agent_run https 2>&1); echo "$out" | grep -q 'up to date'; chk $? "the next run is a no-op"

hdr "20. HTTPS: what a compromised endpoint cannot do"
# A correctly-chained certificate for a key the agent does not hold, with
# SHA256SUMS and meta.json made consistent -- the strongest a hostile server or
# a hostile network can manage without the agent's private key.
EK=$(mktemp); openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$EK" 2>/dev/null
ECSR=$(mktemp); EEXT=$(mktemp)
openssl req -new -key "$EK" -subj "/CN=h.example.com" -out "$ECSR" 2>/dev/null
printf 'subjectAltName=DNS:h.example.com,DNS:alt.h.example.com\n' > "$EEXT"
openssl x509 -req -in "$ECSR" -CA "$T/ca/int.crt" -CAkey "$T/ca/int.key" -set_serial 4242 \
  -days 90 -extfile "$EEXT" -out "$WWW/h-https-$tok/cert.pem" 2>/dev/null
cat "$WWW/h-https-$tok/cert.pem" "$T/ca/int.crt" > "$WWW/h-https-$tok/fullchain.pem"
EFP=$(openssl x509 -in "$WWW/h-https-$tok/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
ESPKI=$(spki_cert "$WWW/h-https-$tok/cert.pem")
rewrite_meta "$WWW/h-https-$tok/meta.json" "$EFP" "$ESPKI"
( cd "$WWW/h-https-$tok" && sha256sum cert.pem chain.pem fullchain.pem meta.json > SHA256SUMS )
BEFORE=$(spki_cert "$HD/cert.pem")
out=$(agent_run https 2>&1); rc=$?
[[ "$(spki_cert "$HD/cert.pem")" == "$BEFORE" ]]; chk $? "a certificate for a foreign key is NOT installed"
[[ "$(spki_key "$HD/privkey.pem")" == "$HSPKI" ]]; chk $? "the local key is untouched"
[[ $rc == 0 ]]; chk $? "and the run does not hard-fail, it asks for enrolment again"
rm -f "$EK" "$ECSR" "$EEXT"

# A private key appearing on the endpoint has to stop the agent dead -- from a
# clean endpoint, so this tests the leak and not the previous tamper.
"$ISSUE" --force h-https >/dev/null 2>&1; agent_run https >/dev/null 2>&1
cp "$HD/privkey.pem" "$WWW/h-https-$tok/privkey.pem"
out=$(agent_run https --force 2>&1); rc=$?
[[ $rc != 0 ]]; chk $? "a private key on the endpoint aborts the run"
echo "$out" | grep -q 'must never be on this endpoint'; chk $? "with an unmistakable message"
out=$("$HOST" doctor 2>&1 || true)
echo "$out" | grep -q 'A PRIVATE KEY IS PUBLISHED OVER HTTPS'; chk $? "doctor screams about it too"
rm -f "$WWW/h-https-$tok/privkey.pem"
"$ISSUE" --force h-https >/dev/null 2>&1; agent_run https >/dev/null 2>&1

hdr "21. token rotation and removal"
out=$("$HOST" token --rotate h-https 2>&1); chk $? "token --rotate"
newtok=$(sed -n 's/^WWW_TOKEN="\(.*\)"/\1/p' "$T/etc/certpull/hosts.d/h-https.conf")
[[ -n $newtok && $newtok != "$tok" ]]; chk $? "the token really changed"
[[ ! -d $WWW/h-https-$tok ]]; chk $? "the old directory is gone, so the old URL stops working"
out=$(agent_run https 2>&1); rc=$?
[[ $rc != 0 ]]; chk $? "an agent still on the old URL fails loudly instead of going quietly stale"
echo "$out" | grep -q 'certpull-host url'; chk $? "and is told where to get the new one"
sed -i "s|^CERT_URL=.*|CERT_URL=\"https://stub/certs/h-https-$newtok\"|" "$T/agenthome/.config/certpull/https.conf"
"$ISSUE" --force h-https >/dev/null 2>&1; chk $? "re-publishing under the new token"
out=$(agent_run https 2>&1); rc=$?
[[ $rc == 0 ]]; chk $? "the agent works again on the new URL (rc=$rc)"

"$HOST" del h-https >/dev/null 2>&1; chk $? "certpull-host del"
[[ -z $(find "$WWW" -maxdepth 1 -name 'h-https-*' 2>/dev/null) ]]; chk $? "del removed the published directory"

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
if [[ $KEEP == 0 && -d $T ]]; then rm -rf "$T"; else echo "sandbox kept at $T"; fi
[[ $FAIL == 0 ]]
