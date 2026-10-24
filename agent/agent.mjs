// An AI agent's MCP client, secured with mTLS + DPoP:
//   1. discover Keycloak from the MCP server's 401 (MCP authorization spec)
//   2. get a token with its certificate (no client secret) and a DPoP proof, so the token is bound to its key
//   3. call tools with a fresh DPoP proof on every request, over mTLS
// Usage: AGENT=notes-agent node agent/agent.mjs
import https from "node:https";
import { Readable } from "node:stream";
import { readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, createHash, sign, randomUUID } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { discoverOAuthProtectedResourceMetadata, discoverAuthorizationServerMetadata } from "@modelcontextprotocol/sdk/client/auth.js";

const AGENT = process.env.AGENT || "notes-agent", MCP_URL = new URL(process.env.MCP_URL || "https://localhost:9444/mcp");
const tls = { ca: readFileSync("certs/ca.crt"), cert: readFileSync(`certs/${AGENT}.crt`), key: readFileSync(`certs/${AGENT}.key`) };
const say = (s) => console.log(s), b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const claims = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url"));

// fetch over mTLS: every connection presents the agent's certificate (streams, so MCP's SSE works too)
function mtlsFetch(url, init = {}) {
  return new Promise((ok, bad) => {
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    const req = https.request(url, { method: init.method || "GET", headers, signal: init.signal, ...tls }, (res) => {
      const body = [204, 304].includes(res.statusCode) ? null : Readable.toWeb(res);
      ok(new Response(body, { status: res.statusCode, headers: Object.entries(res.headers).flatMap(([k, v]) => [].concat(v).map((x) => [k, x])) }));
    });
    req.on("error", bad); if (init.body) req.write(String(init.body)); req.end();
  });
}

// The agent's DPoP key: generated at start-up, kept in memory, never written anywhere
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { kty, crv, x, y } = publicKey.export({ format: "jwk" });
const jkt = createHash("sha256").update(JSON.stringify({ crv, kty, x, y })).digest("base64url");
function proof(htm, url, token) {
  const u = new URL(url), payload = { jti: randomUUID(), htm, htu: u.origin + u.pathname, iat: Math.floor(Date.now() / 1000) };
  if (token) payload.ath = createHash("sha256").update(token).digest("base64url");
  const input = `${b64({ typ: "dpop+jwt", alg: "ES256", jwk: { kty, crv, x, y } })}.${b64(payload)}`;
  return `${input}.${sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}

// 1. Discovery: the MCP server's 401 says where its protected resource metadata lives
say(`→ ${AGENT}: calling ${MCP_URL} without a token`);
const probe = await mtlsFetch(MCP_URL, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}" });
// (the SDK's extractWWWAuthenticateParams only reads Bearer challenges, and this server answers with a DPoP one)
const resourceMetadataUrl = new URL(probe.headers.get("www-authenticate").match(/resource_metadata="([^"]+)"/)[1]);
say(`  ${probe.status}, resource_metadata: ${resourceMetadataUrl}`);
const prm = await discoverOAuthProtectedResourceMetadata(MCP_URL, { resourceMetadataUrl }, mtlsFetch);
const as = await discoverAuthorizationServerMetadata(prm.authorization_servers[0], { fetchFn: mtlsFetch });
say(`→ authorization server: ${as.issuer}  (DPoP required: ${prm.dpop_bound_access_tokens_required})`);

// 2. Token: client_credentials, authenticated by the TLS client certificate, bound by a DPoP proof
say(`→ token request: certificate CN=${AGENT}, no client secret, DPoP key ${jkt.slice(0, 12)}…`);
const tokenRes = await mtlsFetch(as.token_endpoint, {
  method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: proof("POST", as.token_endpoint) },
  body: new URLSearchParams({ grant_type: "client_credentials", client_id: AGENT })
});
const tok = await tokenRes.json();
if (!tokenRes.ok) { say(`  ✖ ${tokenRes.status} ${JSON.stringify(tok)}`); process.exit(1); }
const c = claims(tok.access_token);
say(`  token_type=${tok.token_type}  scope="${c.scope}"  aud=${[].concat(c.aud).join(",")}  cnf.jkt=${c.cnf?.jkt?.slice(0, 12)}…`);
if (process.env.DEBUG_LOG) writeFileSync(process.env.DEBUG_LOG, `${new Date().toISOString()} DEBUG ${AGENT} access_token=${tok.access_token}\n`);

// 3. MCP: every request carries the agent's certificate and a fresh DPoP proof for this token
const dpopFetch = (url, init = {}) => {
  const headers = new Headers(init.headers);
  headers.set("authorization", `DPoP ${tok.access_token}`);
  headers.set("dpop", proof(init.method || "GET", url, tok.access_token));
  return mtlsFetch(url, { ...init, headers });
};
const client = new Client({ name: AGENT, version: "1.0.0" });
try { await client.connect(new StreamableHTTPClientTransport(MCP_URL, { fetch: dpopFetch })); }
catch (e) { say(`  ✖ MCP refused: ${e.message}`); process.exit(1); }
const { tools } = await client.listTools();
say(`→ MCP connected to ${client.getServerVersion().name}: tools ${tools.map((t) => t.name).join(", ")}`);
for (const [name, args] of [["list_notes", {}], ["delete_note", { id: 1 }]]) {
  const r = await client.callTool({ name, arguments: args });
  say(`→ ${name}${Object.keys(args).length ? " " + JSON.stringify(args) : ""}`);
  for (const line of r.content.map((x) => x.text).join("\n").split("\n")) say(`  ${r.isError ? "✖ " : ""}${line}`);
}
await client.close();
