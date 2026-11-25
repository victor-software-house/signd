#!/bin/sh
#MISE description="Check Secure Enclave keys, the access group and the LaunchAgent with the installed Signd.app; a physical Mac only"
# GitHub-hosted runners have no Secure Enclave, so this runs on a Mac before each release.
# It uses /Applications/Signd.app, or the app SIGND_APP names, and the agent on ~/.ssh/signd.sock.
set -eu

app=${SIGND_APP:-/Applications/Signd.app}
signd=$app/Contents/MacOS/signd
work=$(mktemp -d)
name=e2e-hw-$$
tls=e2e-tls-$$
export SSH_AUTH_SOCK=$HOME/.ssh/signd.sock

cleanup() {
  for suffix in "" -ed -rsa -imp -prot -bad -small; do
    "$signd" key delete "$name$suffix" 2> /dev/null || true
  done
  for identity in "$tls" "$tls-other"; do
    "$signd" tls remove "$identity" 2> /dev/null || true
  done
  "$signd" config unset key-lifetime
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "✘ $1" >&2
  exit 1
}

agent_pid() {
  "$signd" status --json | plutil -extract agent.pid raw - 2> /dev/null
}

wait_for_agent() {
  tries=0
  until "$signd" status > /dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 50 ]; then fail "the agent did not answer in 5 seconds"; fi
    sleep 0.1
  done
}

sign_and_verify() {
  printf 'e2e\n' > "$work/message"
  rm -f "$work/message.sig"
  ssh-keygen -Y sign -f "$work/key.pub" -n e2e "$work/message" 2> /dev/null || fail "ssh-keygen -Y sign failed ($1)"
  printf 'e2e %s\n' "$(cut -d' ' -f1,2 "$work/key.pub")" > "$work/allowed"
  ssh-keygen -Y verify -f "$work/allowed" -I e2e -n e2e -s "$work/message.sig" < "$work/message" > /dev/null 2>&1 ||
    fail "the signature does not verify ($1)"
}

"$signd" service enable > /dev/null
"$signd" service enable > /dev/null
wait_for_agent
[ "$(pgrep -x -u "$(id -u)" signd | wc -l | tr -d ' ')" = 1 ] || fail "service enable twice left other than one agent"

# The login hook's command prints nothing and keeps the agent's process when the agent is set up.
old=$(agent_pid)
"$signd" service enable --at-login > "$work/at-login.out"
[ ! -s "$work/at-login.out" ] || fail "service enable --at-login printed output with the agent set up"
[ "$(agent_pid)" = "$old" ] || fail "service enable --at-login replaced a running agent"

# With the login item removed, the same command registers it and starts the agent.
"$signd" service disable > /dev/null
"$signd" service enable --at-login > /dev/null
wait_for_agent
[ "$("$signd" status --json | plutil -extract loginItem raw - 2> /dev/null)" = enabled ] || fail "service enable --at-login did not enable the login item"

old=$(agent_pid)
"$signd" service restart > /dev/null
wait_for_agent
[ "$(agent_pid)" != "$old" ] || fail "service restart kept the same agent"

"$signd" key create "$name" > "$work/key.pub"
grep -q '^ecdsa-sha2-nistp256 ' "$work/key.pub" || fail "key create printed no P-256 public key"
[ "$("$signd" key show "$name")" = "$(cat "$work/key.pub")" ] || fail "key show differs from key create"
ssh-add -L | grep -q "$(cut -d' ' -f2 "$work/key.pub")" || fail "ssh-add -L does not list the new key"
sign_and_verify "first signature"

locked=$(ioreg -n Root -d1 -a | plutil -extract IOConsoleLocked raw - 2> /dev/null || echo unknown)

old=$(agent_pid)
launchctl kickstart -k "gui/$(id -u)/com.victor-software-house.signd"
wait_for_agent
[ "$(agent_pid)" != "$old" ] || fail "the agent did not restart"
sign_and_verify "after a restart"

# A cask upgrade removes the job from launchd and leaves the login item enabled.
launchctl bootout "gui/$(id -u)/com.victor-software-house.signd"
"$signd" service enable > /dev/null
wait_for_agent
sign_and_verify "after service enable restored a removed job"

cat > "$work/probe.swift" << 'SWIFT'
import Foundation
import Security
let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.victor-software-house.signd.key", kSecUseDataProtectionKeychain as String: true, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true]
var result: CFTypeRef?
print(SecItemCopyMatching(query as CFDictionary, &result))
SWIFT
xcrun swiftc -o "$work/probe" "$work/probe.swift"
status=$("$work/probe")
[ "$status" != 0 ] || fail "an ad-hoc signed probe read signd's keys"

"$signd" config set key-lifetime 1s
sign_and_verify "with a 1-second lifetime"
sleep 3
"$signd" status --json | grep -B1 "\"name\" : \"$name\"" | grep -q '"inMemory" : false' || fail "the key stayed in memory past its lifetime"

"$signd" key delete "$name"
if ssh-add -L 2> /dev/null | grep -q "$(cut -d' ' -f2 "$work/key.pub")"; then fail "the deleted key is still listed"; fi

"$signd" config unset key-lifetime

# --local keeps the test keys off iCloud, so no other device receives them.
"$signd" key create "$name-ed" --type ed25519 --local > "$work/key.pub"
[ "$(wc -l < "$work/key.pub" | tr -d ' ')" = 1 ] || fail "key create --type ed25519 printed other than one line"
grep -q '^ssh-ed25519 ' "$work/key.pub" || fail "key create --type ed25519 printed no ssh-ed25519 public key"
sign_and_verify "wrapped Ed25519 key"

"$signd" key create "$name-rsa" --type rsa-3072 --local > "$work/key.pub"
[ "$(wc -l < "$work/key.pub" | tr -d ' ')" = 1 ] || fail "key create --type rsa-3072 printed other than one line"
grep -q '^ssh-rsa ' "$work/key.pub" || fail "key create --type rsa-3072 printed no ssh-rsa public key"
sign_and_verify "wrapped RSA key"

ssh-keygen -q -t ed25519 -N '' -f "$work/plain"
"$signd" key import "$name-imp" - --local < "$work/plain" > /dev/null
"$signd" key show "$name-imp" > "$work/key.pub"
[ "$(cut -d' ' -f1,2 "$work/key.pub")" = "$(cut -d' ' -f1,2 "$work/plain.pub")" ] || fail "the imported key's public key differs from the file's"
sign_and_verify "key imported from stdin"

ssh-keygen -q -t ed25519 -N secret -f "$work/prot"
printf '#!/bin/sh\necho secret\n' > "$work/askpass"
chmod 700 "$work/askpass"
SSH_ASKPASS="$work/askpass" SSH_ASKPASS_REQUIRE=force "$signd" key import "$name-prot" "$work/prot" --local > /dev/null
"$signd" key list | grep -q "^$name-prot " || fail "key list does not show the key imported through ssh-add"
"$signd" key show "$name-prot" > "$work/key.pub"
[ "$(cut -d' ' -f1,2 "$work/key.pub")" = "$(cut -d' ' -f1,2 "$work/prot.pub")" ] || fail "the protected key's public key differs from the file's"
sign_and_verify "protected key imported through ssh-add"
if "$signd" key import "$name-bad" - --local < "$work/prot" > /dev/null 2> "$work/bad.err"; then fail "a protected key on stdin was imported"; fi
grep -q 'file' "$work/bad.err" || fail "the refusal of a protected key on stdin does not mention a file"

ssh-keygen -q -t rsa -b 1024 -N '' -f "$work/small"
if "$signd" key import "$name-small" "$work/small" --local > /dev/null 2> "$work/small.err"; then fail "an RSA 1024 key was imported"; fi
grep -q 'RSA 1024' "$work/small.err" || fail "the refusal of an RSA 1024 key does not name it"
if "$signd" key list | grep -q "^$name-small "; then fail "the refused RSA 1024 key is listed"; fi

# A TLS identity: create, sign its request with a test authority, store the chain, refuse another key's chain, remove.
openssl ecparam -name prime256v1 -genkey -noout -out "$work/ca.key"
openssl req -new -x509 -key "$work/ca.key" -subj "/CN=e2e-authority" -days 1 -out "$work/ca.pem"
printf 'extendedKeyUsage=clientAuth\n' > "$work/client.ext"

sign_request() {
  "$signd" tls csr "$1" --common-name "$1" --organization e2e > "$work/$1.csr" || fail "tls csr failed for $1"
  openssl req -in "$work/$1.csr" -noout -verify 2> /dev/null || fail "the request of $1 does not verify"
  openssl req -in "$work/$1.csr" -noout -subject | grep -q "$1" || fail "the request of $1 does not carry its common name"
  openssl x509 -req -in "$work/$1.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial -days 1 -extfile "$work/client.ext" \
    -out "$work/$1.pem" 2> /dev/null || fail "the test authority did not sign the request of $1"
}

# The chain length that `tls list --json` shows for an identity; nothing when the list lacks it.
tls_chain_length() {
  "$signd" tls list --json > "$work/tls-list.json" || fail "tls list failed"
  index=0
  while listed=$(plutil -extract "$index.name" raw "$work/tls-list.json" 2> /dev/null); do
    if [ "$listed" = "$1" ]; then
      plutil -extract "$index.chainLength" raw "$work/tls-list.json"
      return
    fi
    index=$((index + 1))
  done
}

"$signd" tls create "$tls" || fail "tls create failed"
if "$signd" tls create "$tls" 2> /dev/null; then fail "tls create replaced an identity that exists"; fi
if "$signd" key list | grep -q "$tls"; then fail "key list shows the TLS identity"; fi
sign_request "$tls"
cat "$work/$tls.pem" "$work/ca.pem" | "$signd" tls store "$tls" || fail "tls store refused the chain signed for its key"
[ "$(tls_chain_length "$tls")" = 2 ] || fail "tls list does not show the stored chain of 2 certificates"

"$signd" tls create "$tls-other" || fail "tls create failed for the second identity"
sign_request "$tls-other"
if cat "$work/$tls-other.pem" "$work/ca.pem" | "$signd" tls store "$tls" 2> "$work/mismatch.err"; then fail "tls store took a chain for another key"; fi
grep -q 'another key' "$work/mismatch.err" || fail "the refusal of a chain for another key does not name the mismatch"

"$signd" tls remove "$tls" || fail "tls remove failed"
[ -z "$(tls_chain_length "$tls")" ] || fail "tls list still shows the removed identity"
"$signd" tls remove "$tls-other" || fail "tls remove failed for the second identity"
if "$signd" tls remove "$tls" 2> /dev/null; then fail "tls remove succeeded for a removed identity"; fi

echo "✔ Secure Enclave key created, listed, signed before and after an agent restart (screen locked: $locked), hidden from an ad-hoc probe (status $status), dropped from memory after its lifetime, and deleted; wrapped Ed25519 and RSA keys created, an Ed25519 key imported from stdin, a protected key imported through ssh-add, and an RSA 1024 key refused; a TLS identity created, signed through a test authority, stored, kept apart from a chain for another key, and removed"
