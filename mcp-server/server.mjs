// Notes MCP server, secured two ways:
//   mTLS: only agents with a certificate from our CA get past the first check.
//   DPoP: every call needs a Keycloak token for this server, bound to the agent's key, with a fresh proof.
// Unauthenticated calls get a 401 pointing at the protected resource metadata (MCP authorization spec, RFC 9728).
import https from "node:https";
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, createVerify, verify as verifySig } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const ISSUER = process.env.ISSUER, JWKS_URL = process.env.JWKS_URL;
const ORIGIN = process.env.PUBLIC_URL || "https://localhost:9444", RESOURCE = `${ORIGIN}/mcp`;
const PRM = `${ORIGIN}/.well-known/oauth-protected-resource/mcp`;
const ca = readFileSync("certs/ca.crt");
const sha256 = (s) => createHash("sha256").update(s).digest("base64url");
const part = (s) => JSON.parse(Buffer.from(s, "base64url"));
const seen = new Map(); // jti -> expiry, so a captured proof can't be replayed

let keys = null;
async function jwks() {
  if (keys) return keys;
  const body = await new Promise((ok, bad) => https.get(JWKS_URL, { ca }, (r) => { let d = ""; r.on("data", (c) => (d += c)); r.on("end", () => ok(d)); }).on("error", bad));
  keys = Object.fromEntries(JSON.parse(body).keys.filter((k) => k.use === "sig").map((k) => [k.kid, createPublicKey({ key: k, format: "jwk" })]));
  return keys;
}

async function verifyToken(token) {
  const [h, p, s] = token.split(".");
  const key = (await jwks())[part(h).kid], claims = part(p);
  if (!key || !createVerify("RSA-SHA256").update(`${h}.${p}`).verify(key, Buffer.from(s, "base64url"))) throw new Error("bad token signature");
  if (claims.iss !== ISSUER) throw new Error("wrong issuer");
  if (claims.exp * 1000 < Date.now()) throw new Error("token expired");
  if (![].concat(claims.aud).includes(RESOURCE)) throw new Error("token is not for this MCP server (aud)");
  return claims;
}

// RFC 9449 section 4.3: the checks a resource server makes on every DPoP proof
function verifyProof(proof, req, token) {
  if (!proof) throw new Error("missing DPoP proof");
  const [h, p, s] = proof.split("."), header = part(h), claims = part(p);
  if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !header.jwk || header.jwk.d) throw new Error("malformed DPoP proof");
  const ok = verifySig("sha256", Buffer.from(`${h}.${p}`), { key: createPublicKey({ key: header.jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  if (!ok) throw new Error("bad proof signature");
  if (claims.htm !== req.method || claims.htu !== ORIGIN + req.url.split("?")[0]) throw new Error("proof is for a different request");
  if (Math.abs(Date.now() / 1000 - claims.iat) > 60) throw new Error("proof is too old");
  if (seen.has(claims.jti)) throw new Error("proof already used (replay)");
  seen.set(claims.jti, Date.now() + 120_000);
  if (claims.ath !== sha256(token)) throw new Error("proof is for a different token");
  const { crv, kty, x, y } = header.jwk;
  return sha256(JSON.stringify({ crv, kty, x, y })); // RFC 7638 thumbprint of the proof key
}

// The tools. Each one checks the scope it needs: least privilege per agent.
const NOTES = ["Rotate the agent certificates on Friday", "Review MCP tool permissions"];
function mcpServer() {
  const server = new McpServer({ name: "notes", version: "1.0.0" });
  const need = (scope, extra) => {
    if (!extra.authInfo.scopes.includes(scope)) throw new Error(`insufficient_scope: ${extra.authInfo.clientId} needs ${scope}`);
  };
  server.registerTool("list_notes", { description: "List the team's notes" }, async (extra) => {
    need("notes:read", extra);
    return { content: [{ type: "text", text: NOTES.map((n, i) => `${i + 1}. ${n}`).join("\n") }] };
  });
  server.registerTool("delete_note", { description: "Delete a note", inputSchema: { id: z.number() } }, async ({ id }, extra) => {
    need("notes:write", extra);
    return { content: [{ type: "text", text: `deleted note ${id}` }] };
  });
  return server;
}

const tls = { key: readFileSync("certs/server.key"), cert: readFileSync("certs/server.crt"), ca, requestCert: true, rejectUnauthorized: false };
const server = https.createServer(tls, async (req, res) => {
  const json = (code, body, extra = {}) => { res.writeHead(code, { "Content-Type": "application/json", ...extra }); res.end(JSON.stringify(body)); };
  // mTLS first: no certificate, or one our CA didn't sign, and nothing else happens
  if (!req.socket.authorized) {
    const why = req.socket.getPeerCertificate().subject ? `certificate not signed by our CA (${req.socket.authorizationError})` : "no client certificate";
    console.log(`403 untrusted client: ${why}`);
    return json(403, { error: "untrusted_client", error_description: why });
  }
  const agent = req.socket.getPeerCertificate().subject.CN;
  const path = req.url.split("?")[0];
  if (path === "/.well-known/oauth-protected-resource/mcp") {
    return json(200, { resource: RESOURCE, authorization_servers: [ISSUER], scopes_supported: ["notes:read", "notes:write"],
      dpop_signing_alg_values_supported: ["ES256"], dpop_bound_access_tokens_required: true });
  }
  if (path !== "/mcp") return json(404, { error: "not found" });
  try {
    const [scheme, token] = (req.headers.authorization || "").split(" ");
    if (scheme !== "DPoP") throw new Error(`expected the DPoP scheme, got ${scheme || "nothing"}`);
    const claims = await verifyToken(token);
    const jkt = verifyProof(req.headers.dpop, req, token);
    if (claims.cnf?.jkt !== jkt) throw new Error("token is not bound to your key");
    if (claims.azp !== agent) throw new Error(`token belongs to ${claims.azp}, but your certificate says ${agent}`);
    req.auth = { token, clientId: claims.azp, scopes: (claims.scope || "").split(" "), expiresAt: claims.exp };
  } catch (e) {
    console.log(`401 ${agent}: ${e.message}`);
    return json(401, { error: "invalid_token", error_description: e.message },
      { "WWW-Authenticate": `DPoP error="invalid_token", algs="ES256", resource_metadata="${PRM}"` });
  }
  const body = await new Promise((ok) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => ok(d ? JSON.parse(d) : undefined)); });
  console.log(`200 ${agent} ${body?.method ?? req.method}${body?.params?.name ? " " + body.params.name : ""}`);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  const mcp = mcpServer();
  res.on("close", () => { transport.close(); mcp.close(); });
  await mcp.connect(transport);
  await transport.handleRequest(req, res, body);
  for (const [jti, exp] of seen) if (exp < Date.now()) seen.delete(jti);
});
server.listen(9444, () => console.log(`notes MCP server on ${RESOURCE} (mTLS + DPoP)`));
