#!/usr/bin/env bash
# Demo PKI for agents: a CA that Keycloak and the MCP server trust, one server cert for both,
# a cert per agent, and a rogue agent from a CA nobody trusts. Use your real PKI in production.
set -euo pipefail
mkdir -p certs && cd certs

# 1. Certificate authority: the root of trust for agent identities
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=AIS Demo CA" -keyout ca.key -out ca.crt

# 2. HTTPS certificate for Keycloak and the MCP server
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out server.crt \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:keycloak,DNS:notes-mcp\nextendedKeyUsage=serverAuth")

# 3. One certificate per agent: the CN is the agent's identity (its Keycloak client ID)
for name in notes-agent support-agent; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$name/O=Acme" -keyout $name.key -out $name.csr
  openssl x509 -req -in $name.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out $name.crt \
    -extfile <(printf "extendedKeyUsage=clientAuth")
done

# 4. A rogue agent: same name, signed by a CA nobody trusts
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Evil CA" -keyout evil-ca.key -out evil-ca.crt
openssl req -newkey rsa:2048 -nodes -subj "/CN=notes-agent/O=Acme" -keyout rogue.key -out rogue.csr
openssl x509 -req -in rogue.csr -CA evil-ca.crt -CAkey evil-ca.key -CAcreateserial -days 30 -out rogue.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth")

# 5. Truststore Keycloak uses to verify agent certificates
keytool -importcert -noprompt -alias ais-demo-ca -file ca.crt -keystore truststore.p12 -storetype PKCS12 -storepass changeit
rm -f *.csr *.srl
chmod 644 *.key  # demo only: lets the containers read the keys
