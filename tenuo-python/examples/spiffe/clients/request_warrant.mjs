// Request a warrant from a Tenuo SPIFFE issuer over HTTP, with nothing but Node's standard library.
//
// It shows that an agent in any language can speak the single-request exchanges
// described under "JWT wire protocol" and "Forwarded identity wire protocol" in
// docs/spiffe.md. To call tools with the warrant, sign each call with the holder
// key using the Tenuo SDK for your language.
//
//   node request_warrant.mjs URL AUDIENCE TASK_ID            # identity forwarded by a mesh sidecar
//   node request_warrant.mjs URL AUDIENCE TASK_ID JWT_SVID   # a JWT-SVID as bearer token
//
// Prints {"status", "warrant" | "error" and "message", "holder"} as JSON. Needs Node 18 or newer.
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const [url, audience, task, token] = process.argv.slice(2);
if (!url || !audience || !task) {
  console.error("usage: node request_warrant.mjs URL AUDIENCE TASK_ID [JWT_SVID]");
  process.exit(2);
}

// A JWT-SVID is a bearer token: whoever sees it can use it. It goes over HTTPS only,
// except to this machine. Without a token there is nothing to steal, and plain HTTP
// is what a mesh sidecar expects.
const target = new URL(url);
const loopback = ["localhost", "[::1]"].includes(target.hostname) || /^127\.\d+\.\d+\.\d+$/.test(target.hostname);
if (!["https:", "http:"].includes(target.protocol) || (token && target.protocol !== "https:" && !loopback)) {
  console.error("A JWT-SVID is a bearer token: use https:// (http:// is allowed for loopback only)");
  process.exit(2);
}

// The holder key: an Ed25519 key pair that never leaves this process.
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const holder = publicKey.export({ format: "der", type: "spki" }).subarray(-32); // The raw 32-byte public key.

// The statement the holder key signs. Every field has a fixed width.
const sha256 = (text) => createHash("sha256").update(text, "utf8").digest();
const timestamp = Math.floor(Date.now() / 1000);
const time = Buffer.alloc(8);
time.writeBigUInt64BE(BigInt(timestamp));
const nonce = randomBytes(16); // A new one for every request.
const statement = token
  ? Buffer.concat([
      Buffer.from("tenuo.spiffe.jwt-holder-binding.v1\0", "ascii"),
      sha256(token), // The token exactly as sent in the header.
      holder,
      time,
      nonce,
      sha256(audience),
      sha256(task),
    ])
  : Buffer.concat([
      Buffer.from("tenuo.spiffe.forwarded-holder-binding.v1\0", "ascii"),
      holder,
      time,
      nonce,
      sha256(audience),
      sha256(task),
    ]);
const signature = sign(null, statement, privateKey);

const response = await fetch(url, {
  method: "POST",
  redirect: "error", // Never follow a redirect: it could carry the token to another host.
  headers: {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  },
  body: JSON.stringify({
    v: 1,
    holder: holder.toString("base64"),
    task,
    timestamp,
    nonce: nonce.toString("base64"),
    signature: signature.toString("base64"),
  }),
});
const reply = await response.json();
console.log(JSON.stringify({ status: response.status, ...reply, holder: holder.toString("base64") }));
process.exit(response.ok ? 0 : 1);
