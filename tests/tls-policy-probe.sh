#!/bin/bash
# Which servers this machine can still talk to under each crypto policy.
# Run INSIDE a container of the image (needs network):
#   docker run --rm -v "$PWD/tests:/tests:ro" hardened-linux:latest /tests/tls-policy-probe.sh
#
# For each policy, one TLS handshake per endpoint with openssl s_client:
# the registry bootc pulls from, GitHub, the four NTS-KE servers chrony uses
# (port 4460, ALPN ntske/1), the CentOS mirror, and example.com. The policy
# is switched inside this throwaway container only.
set -u
ENDPOINTS="quay.io:443 github.com:443 mirror.stream.centos.org:443 www.example.com:443
time.cloudflare.com:4460 nts.netnod.se:4460 ptbtime1.ptb.de:4460 ptbtime2.ptb.de:4460"

probe() {
  for h in $ENDPOINTS; do
    a=""; case $h in *:4460) a="-alpn ntske/1";; esac
    r=$(timeout 15 openssl s_client -connect "$h" -servername "${h%:*}" $a </dev/null 2>&1)
    cipher=$(echo "$r" | grep -m1 -oE '^New, [^,]*, Cipher is [^ ]*' | sed 's/^New, //')
    kex=$(echo "$r" | grep -m1 -E '^Negotiated TLS1.3 group|^Peer Temp Key' | sed 's/^Negotiated TLS1.3 group: /group /; s/^Peer Temp Key: /ECDHE /')
    ver=$(echo "$r" | grep -m1 -E '^Verification|verify error' | sed 's/^Verification: //')
    printf '  %-30s %-44s %-28s %s\n' "$h" "${cipher:-}" "${kex:-}" "${ver:-}"
  done
}

echo "image policy: $(update-crypto-policies --show)"
for p in DEFAULT FUTURE FUTURE:INTERNET-COMPAT; do
  update-crypto-policies --no-reload --set "$p" >/dev/null 2>&1
  echo; echo "== $(update-crypto-policies --show)"
  probe
done
echo
echo "FUTURE:INTERNET-COMPAT, TLS 1.3 suites: $(openssl ciphers -s -tls1_3)"
echo "protocol lines in the OpenSSL back end:"
grep -hE '^(TLS|DTLS)\.(Min|Max)Protocol' /etc/crypto-policies/back-ends/opensslcnf.config | sed 's/^/  /'
# `openssl s_client -tls1_2` sets the protocol range itself and so bypasses
# the policy; a client that only caps the maximum at TLS 1.2 shows what an
# ordinary program gets.
echo "a client capped at TLS 1.2 against github.com (which supports it):"
timeout 20 python3 -c '
import socket, ssl
c = ssl.create_default_context(); c.maximum_version = ssl.TLSVersion.TLSv1_2
try:
    with socket.create_connection(("github.com", 443), timeout=10) as s, c.wrap_socket(s, server_hostname="github.com") as t:
        print("  connected:", t.version(), t.cipher()[0])
except Exception as e:
    print("  refused:", type(e).__name__, e)
'  
