# Hosted-service adapter on the holder Runtime

Core owns parse, identity, session bind, SRL install, and receipt collection.
A hosted adapter should become HTTP + product policy around `Runtime`.

## What stays in the adapter

- Reading a connect token from the environment
- Choosing `local_base` for a relative `/v1` token (loopback or hosted)
- Adding a scheme to a scheme-less hostname, if the product wants one
- Agent claim, tenant and trusted-root discovery
- Trigger fire / warrant retrieval
- Receipt upload, signer registration, approval polling, heartbeat
- Schema reporting and hosted diagnostics

## Migration sketch (`tenuo-cloud`)

```python
from tenuo import ConnectToken, HolderIdentity, Runtime

token = ConnectToken.parse(raw_token)
if token.needs_endpoint_base:
    token.resolve_endpoint(local_base)  # adapter supplies this

identity = HolderIdentity.load_or_create(key_path)  # or generate()
# identity.signing_key / identity.public_key are derived; never log repr()

roots = discover_trusted_roots(token)          # HTTP
srl = fetch_signed_revocation_list(token)      # HTTP, optional

runtime = Runtime(
    identity=identity,
    trusted_roots=roots,
    revocation_list=srl,
    receipts="collect",
)

warrant = fire_trigger(token, trigger)         # HTTP
session = runtime.session_from_wire(warrant)

with runtime.session_scope(session):
    protected_tool(...)

batch = runtime.peek_receipts()
persist_retry_buffer(batch)
runtime.acknowledge_receipts(len(batch))
for receipt in batch:
    upload_receipt(receipt)                    # drop from adapter retry buffer after 2xx

runtime.apply_revocation_list(fetch_signed_revocation_list(token))
```

Minimum core version for this adapter: **`tenuo==0.2.6`**.

## Receipt retry

`drain_receipts()` is a non-consuming snapshot (same as `peek_receipts()`).
A receipt is removed only by `acknowledge_receipts(n)`. Prefer peek → durable
copy → ack so a crash between peek and persist cannot drop evidence. Do not
treat an acknowledged receipt as uploaded until the ingest call succeeds.

`DeferredEmitter.flush()` is now honest: it does not return `True` after a
sink failure. Transient sink errors retry the same signed artifact.

## Cloud Python code that can be deleted after adoption

After `tenuo-cloud` depends on `tenuo>=0.2.6` and switches to `Runtime`:

| Cloud module / helper | Replacement in core |
|---|---|
| Local `parse_connect_token` / `normalize_endpoint` | `ConnectToken.parse` + `resolve_endpoint` |
| `load_or_create_holder_key` / mismatched key-pair loaders | `HolderIdentity` / `HolderIdentity.load_or_create` |
| Assembling `Authorizer` + signing key + SRL for each warrant | `Runtime.session_from_wire` + `session_scope` |
| `CloudReceiptSink` wired through `DeferredEmitter` as the only outbox | `runtime.peek_receipts()` / `acknowledge_receipts()` + Cloud HTTP upload |
| Per-request receipt callbacks that re-implement FIFO buffering | Runtime aggregate collector |

Keep in Cloud: claim, tenant / `.well-known` roots, trigger fire, receipt
ingest HTTP, authorizer register / heartbeat, approvals, schema report, doctor.
