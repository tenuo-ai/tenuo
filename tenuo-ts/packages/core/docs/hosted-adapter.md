# Hosted-service adapter on the holder Runtime

Core owns parse, identity, session bind, SRL install, and receipt collection.
A hosted adapter should become HTTP + product policy around `Runtime`.

## What stays in the adapter

- Reading a connect token from the environment
- Choosing `localBase` for a relative `/v1` token (loopback or hosted)
- Adding a scheme to a scheme-less hostname, if the product wants one
- Agent claim, tenant and trusted-root discovery
- Trigger fire / warrant retrieval
- Receipt upload, signer registration, approval polling, heartbeat
- Schema reporting and hosted diagnostics

## Migration sketch

```ts
const token = createTenuo.parseConnectToken(rawToken);
if (token.needsEndpointBase) {
  token.resolveEndpoint({ localBase }); // adapter supplies this
}
const identity = holderKey
  ? createTenuo.identity(holderKey)
  : createTenuo.generateIdentity();
// adapter persists identity.holderKey if it wants a stable key

const roots = await discoverTrustedRoots(token); // HTTP
const srl = await fetchSignedRevocationList(token); // HTTP, optional

const runtime = createTenuo.runtime({
  identity,
  trustedRoots: roots,
  ...(srl !== undefined ? { revocationList: srl } : {}),
  receipts: "collect",
});

const warrant = await fireTrigger(token, trigger); // HTTP
const session = runtime.sessionFromWire(warrant);

await tool.execute(args, { session });
const presented = runtime.tenuo.present(session, name, args);
runtime.tenuo.mcp.attach(session, name, args); // no onReceipt required

const batch = session.peekReceipts();
await persistRetryBuffer(batch);
session.acknowledgeReceipts(batch.length);
for (const receipt of batch) {
  await uploadReceipt(receipt); // ack in the adapter buffer only after 2xx
}

runtime.applyRevocationList(await fetchSignedRevocationList(token));
```

## Receipt retry

`drainReceipts()` is at-most-once from the in-process buffer. Prefer
`peekReceipts()` + durable copy + `acknowledgeReceipts(n)` so a crash between
peek and persist cannot drop evidence. Do not treat a drained receipt as
uploaded until the ingest call succeeds.

## `@tenuo/cloud` compatibility

When thinning `@tenuo/cloud`:

1. Replace local `parseConnectToken` / `normalizeEndpoint` with
   `createTenuo.parseConnectToken`. After parse, `endpoint` is a bare origin
   (no `/v1`). Append `/v1/` in the HTTP client. For `/v1` tokens, call
   `resolveEndpoint({ localBase: process.env.TENUO_API_URL })` in the adapter
   — core will not default to localhost or invent `https://`.
2. Replace `loadOrCreateHolderKey` + raw `Uint8Array` with
   `createTenuo.identity` / `generateIdentity`. Keep `node:fs` persistence in
   the Cloud package (or a future `@tenuo/node`).
3. Hold a `Runtime` instead of assembling `createTenuo` + `sessionFromWire` +
   a `receiptSink` passed to every `onReceipt`. Use `runtime.sessionFromWire`
   and `session.drainReceipts()` / peek+ack.
4. Keep Cloud-only HTTP: claim, tenant, `.well-known` roots, trigger fire,
   receipt ingest, authorizer register/heartbeat, approvals, schema report,
   doctor.
5. Peer-depend on `@tenuo/core@0.2.6-beta.0`. `createTenuo.publicKeyFromHolderKey`
   remains; `identity.publicKey` is the same handle.
6. Stop uploading from a fire-and-forget `onReceipt` Promise chain. Drain or
   peek/ack, then upload from the adapter retry buffer.
