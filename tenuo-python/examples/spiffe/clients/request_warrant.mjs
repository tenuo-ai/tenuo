// Request a warrant from a Tenuo SPIFFE issuer over HTTP, with nothing but Node's standard library.
//
// It shows that an agent in any language can speak the single-request exchanges
// described under "JWT wire protocol" and "Forwarded identity wire protocol" in
// docs/spiffe.md.
//
// A warrant is only usable with the private half of the holder key it was issued
// to: every tool call is signed with it. So the caller owns that key.
//
// In an agent, import the function and keep the key in memory:
//
//   import { generateKeyPairSync } from "node:crypto";
//   import { requestWarrant } from "./request_warrant.mjs";
//   const holderKey = generateKeyPairSync("ed25519").privateKey;
//   const { warrant } = await requestWarrant({ url, audience, task, holderKey });
//   // Sign each tool call with holderKey, using the Tenuo SDK for your language.
//
// From a shell, name a file for the key. It is created (readable by you alone) if
// it does not exist, and reused if it does:
//
//   HOLDER_KEY_FILE=holder.pem node request_warrant.mjs URL AUDIENCE TASK_ID            # sidecar-forwarded identity
//   HOLDER_KEY_FILE=holder.pem node request_warrant.mjs URL AUDIENCE TASK_ID JWT_SVID   # a JWT-SVID as bearer token
//
// Prints {"status", "warrant" | "error" and "message", "holder"} as JSON. Needs Node 18 or newer.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

// Returns {status, holder, warrant} on success, or {status, holder, error, message}.
// `holderKey` is an Ed25519 private key (a KeyObject) that the caller keeps.
export async function requestWarrant({ url, audience, task, token, holderKey }) {
  // A JWT-SVID is a bearer token: whoever sees it can use it. It goes over HTTPS only,
  // except to this machine. Without a token there is nothing to steal, and plain HTTP
  // is what a mesh sidecar expects.
  const target = new URL(url);
  const loopback = ["localhost", "[::1]"].includes(target.hostname) || /^127\.\d+\.\d+\.\d+$/.test(target.hostname);
  if (!["https:", "http:"].includes(target.protocol) || (token && target.protocol !== "https:" && !loopback)) {
    throw new Error("A JWT-SVID is a bearer token: use https:// (http:// is allowed for loopback only)");
  }
  if (holderKey?.type !== "private" || holderKey.asymmetricKeyType !== "ed25519") {
    throw new Error("holderKey must be an Ed25519 private key that the caller keeps");
  }
  const holder = createPublicKey(holderKey).export({ format: "der", type: "spki" }).subarray(-32); // The raw public key.

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
  const signature = sign(null, statement, holderKey);

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
  return { status: response.status, ...(await response.json()), holder: holder.toString("base64") };
}

// The holder key for the command line: kept in the file HOLDER_KEY_FILE names.
function holderKeyFromFile(path) {
  if (existsSync(path)) {
    return createPrivateKey(readFileSync(path));
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  // "wx": never overwrite a key that appeared meanwhile. 0600: readable by the owner alone.
  writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600, flag: "wx" });
  return privateKey;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [url, audience, task, token] = process.argv.slice(2);
  const keyFile = process.env.HOLDER_KEY_FILE;
  if (!url || !audience || !task || !keyFile) {
    console.error("usage: HOLDER_KEY_FILE=holder.pem node request_warrant.mjs URL AUDIENCE TASK_ID [JWT_SVID]");
    console.error("The warrant is usable only with the key in HOLDER_KEY_FILE, which is created if missing.");
    process.exit(2);
  }
  try {
    const reply = await requestWarrant({ url, audience, task, token, holderKey: holderKeyFromFile(keyFile) });
    console.log(JSON.stringify(reply));
    process.exit(reply.status === 200 ? 0 : 1);
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
}
