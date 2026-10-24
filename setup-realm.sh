#!/usr/bin/env bash
# Realm for AI agents: each agent is a client that authenticates with its certificate (no secret),
# gets DPoP-bound tokens, and only the scopes it needs, with the MCP server as the audience.
# Keycloak formats the subject as "O=Acme, CN=notes-agent", so the pattern matches CN anywhere.
set -euo pipefail
MCP=https://localhost:9444/mcp
kcadm() { docker exec keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
kcadm config credentials --server http://localhost:8080 --realm master --user admin --password "$KC_ADMIN_PASSWORD"
kcadm create realms -s realm=acme -s enabled=true

# One client scope per permission. Each puts the MCP server in the token's audience.
for scope in notes:read notes:write; do
  id=$(kcadm create client-scopes -r acme -s name=$scope -s protocol=openid-connect \
    -s 'attributes."include.in.token.scope"=true' -i)
  kcadm create client-scopes/$id/protocol-mappers/models -r acme -s name=mcp-audience \
    -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.custom.audience\"=$MCP" -s 'config."access.token.claim"=true'
done

# Agents: certificate auth, DPoP-bound tokens, least privilege
agent() {
  local name=$1; shift
  kcadm create clients -r acme -s clientId=$name -s publicClient=false -s serviceAccountsEnabled=true \
    -s standardFlowEnabled=false -s directAccessGrantsEnabled=false \
    -s clientAuthenticatorType=client-x509 \
    -s "attributes.\"x509.subjectdn\"=(.*, )?CN=$name(, .*)?" \
    -s 'attributes."x509.allow.regex.pattern.comparison"=true' \
    -s 'attributes."dpop.bound.access.tokens"=true' \
    -s "defaultClientScopes=$(printf '%s\n' basic "$@" | jq -R . | jq -sc .)"
}
agent notes-agent notes:read          # reads notes, can't delete them
agent support-agent                   # a different agent, with no notes access at all
