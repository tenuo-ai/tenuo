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

const batch = runtime.peekReceipts();
await persistRetryBuffer(batch);
runtime.acknowledgeReceipts(batch.length);
for (const receipt of batch) {
  await uploadReceipt(receipt); // ack in the adapter buffer only after 2xx
}

runtime.applyRevocationList(await fetchSignedRevocationList(token));
```

## Receipt retry

`drainReceipts()` is a snapshot of the in-process buffer. It does not remove
anything. Prefer `peekReceipts()` + durable copy + `acknowledgeReceipts(n)` so a
crash between peek and persist cannot drop evidence. Do not treat a drained
receipt as uploaded until the ingest call succeeds.
