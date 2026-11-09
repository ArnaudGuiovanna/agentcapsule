#!/bin/sh
# Lab certificates for deploy/interop (P-256, valid DAYS days, default 30).
#
#   deploy/interop/make-certs.sh <new-dir> [--test-identities]
#
# Two authorities: the Directory CA (edge server and control-plane client) and
# the SLIM CA (node server and platform bridge client), so a SLIM credential
# never opens Directory. Keys mounted into containers are made readable by their
# unprivileged users (mode 0644): fine for a lab; on a host, give each key to its
# container user instead (HAProxy 99, SLIM 65532) with mode 0400, and keep the
# ca/ directory offline. --test-identities adds the identities the qualification
# expects to be refused.
set -eu
[ $# -ge 1 ] || { echo "usage: $0 <new-dir> [--test-identities]" >&2; exit 2; }
out=$1
days=${DAYS:-30}
[ ! -e "$out" ] || { echo "$out already exists" >&2; exit 1; }
umask 077
mkdir -p "$out/ca" "$out/directory-edge" "$out/slim" "$out/control-plane" "$out/slim-bridge"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
ca() { # ca <key> <cert> <cn>
	key "$1"
	openssl req -x509 -new -key "$1" -sha256 -days "$days" -subj "/CN=$3" \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$2"
}
sign() { # sign <ca-key> <ca-cert> <key> <cert> <cn> <server|client>
	key "$3"
	if [ "$6" = server ]; then
		printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n' >"$tmp/ext"
	else
		printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' >"$tmp/ext"
	fi
	openssl req -new -key "$3" -subj "/CN=$5" -out "$tmp/csr"
	openssl x509 -req -in "$tmp/csr" -CA "$2" -CAkey "$1" -CAcreateserial -CAserial "$tmp/serial" \
		-days "$days" -sha256 -extfile "$tmp/ext" -out "$4" 2>/dev/null
}

ca "$out/ca/directory-ca.key" "$out/ca/directory-ca.pem" "Agent Capsule Directory CA"
ca "$out/ca/slim-ca.key" "$out/ca/slim-ca.pem" "Agent Capsule SLIM CA"

sign "$out/ca/directory-ca.key" "$out/ca/directory-ca.pem" "$tmp/edge.key" "$tmp/edge.crt" agentcapsule-directory server
cat "$tmp/edge.crt" "$tmp/edge.key" >"$out/directory-edge/edge.pem"
cp "$out/ca/directory-ca.pem" "$out/directory-edge/ca.pem"
sign "$out/ca/directory-ca.key" "$out/ca/directory-ca.pem" "$out/control-plane/directory.key" "$out/control-plane/directory.crt" agentcapsule-control-plane client
cp "$out/ca/directory-ca.pem" "$out/control-plane/directory-ca.pem"

sign "$out/ca/slim-ca.key" "$out/ca/slim-ca.pem" "$out/slim/server.key" "$out/slim/server.pem" agentcapsule-slim server
cp "$out/ca/slim-ca.pem" "$out/slim/ca.pem"
sign "$out/ca/slim-ca.key" "$out/ca/slim-ca.pem" "$out/slim-bridge/client.key" "$out/slim-bridge/client.crt" agentcapsule-slim-bridge client
cp "$out/ca/slim-ca.pem" "$out/slim-bridge/slim-ca.pem"

if [ "${2:-}" = --test-identities ]; then
	mkdir "$out/test"
	# Right authority, wrong name: the Directory edge must refuse it.
	sign "$out/ca/directory-ca.key" "$out/ca/directory-ca.pem" "$out/test/other.key" "$out/test/other.crt" some-other-workload client
	# Unknown authority with the expected names: both services must refuse it.
	ca "$tmp/rogue-ca.key" "$tmp/rogue-ca.pem" "Rogue CA"
	sign "$tmp/rogue-ca.key" "$tmp/rogue-ca.pem" "$out/test/rogue.key" "$out/test/rogue.crt" agentcapsule-control-plane client
fi

chmod 0755 "$out" "$out/directory-edge" "$out/slim"
chmod 0644 "$out/directory-edge/"* "$out/slim/"*
echo "certificates written to $out"
