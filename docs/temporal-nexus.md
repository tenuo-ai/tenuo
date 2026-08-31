---
title: Temporal Nexus Authorization
description: Experimental Tenuo authorization across Temporal Nexus namespace boundaries
---

# Temporal Nexus Authorization

> Experimental surface. Tenuo can now emit and verify authorization headers for
> Temporal Nexus operations, and can carry verified authority into
> workflow-backed Nexus operations through an explicit envelope/bootstrap path.

Temporal Nexus lets one Temporal namespace expose a service contract that
workflows in another namespace can call through a named endpoint. That is the
commercially important boundary for Tenuo: a caller namespace should be able to
bring narrowly delegated authority to a handler namespace without sharing broad
service credentials or relying only on ambient namespace identity.

## Goal

Let a privileged handler namespace verify exactly what a caller workflow is
allowed to do:

- which Nexus service and operation may be called;
- which tenant, record, file, payment, ticket, or resource is in scope;
- which operation arguments are permitted;
- who delegated the authority; and
- whether that authority is expired or revoked.

The handler namespace should not need to trust the caller namespace broadly,
and the caller namespace should not receive privileged handler credentials.

## Example story

A workflow in `agent-namespace` calls a Nexus endpoint exposed by
`billing-namespace`:

```python
nexus_client = workflow.create_nexus_client(
    service=BillingService,
    endpoint="billing-prod",
)

await tenuo_execute_nexus_operation(
    nexus_client,
    BillingService.refund,
    RefundInput(order_id="ord_123", amount_cents=5000),
    warrant=refund_warrant,
    key_id="agent-key",
)
```

The `billing-namespace` handler verifies the Tenuo warrant before performing
the refund:

```python
class BillingServiceHandler:
    @tenuo_nexus_operation(config, endpoint="billing-prod")
    async def refund(self, ctx, input: RefundInput) -> RefundOutput:
        ...
```

If the warrant only allows `order_id="ord_123"` and
`amount_cents <= 5000`, a larger or different refund is denied at the handler
boundary, even though the Nexus endpoint itself is reachable.

## Supported experimental surfaces

### Caller workflow helper

`tenuo_execute_nexus_operation(...)` and
`tenuo_start_nexus_operation(...)` mirror the successful
`tenuo_execute_activity(...)` shape for Nexus callers:

- read the current workflow warrant, or accept a per-call `warrant=`;
- require `key_id=` when a per-call warrant is supplied;
- include the full delegated `warrant_chain`;
- sign proof-of-possession over Nexus-specific context; and
- pass Tenuo material through the Nexus operation `headers=` argument.

The proof input currently binds:

- endpoint name;
- service name;
- operation name;
- normalized operation input.

`tenuo_nexus_headers(...)` is also available as a lower-level escape hatch for
advanced wiring and tests.

### Handler verifier

The handler-side surface verifies `ctx.headers` before user code runs:

- warrant chain roots, signatures, linkage, expiry, and revocation;
- PoP against the caller's holder key;
- service and operation binding;
- operation input constraints; and
- Nexus-native unauthorized errors via `tenuo_nexus_operation(...,
  raise_nexus_error=True)` behavior.

Authorization failures should raise Nexus-native non-retryable errors so
Temporal does not retry permanent denials.

The supported APIs are:

- `verify_nexus_operation(ctx, input, config, ...)`
- `tenuo_nexus_operation(config, ...)`
- `nexus_tool_name(endpoint, operation, service=...)`

### Workflow-backed Nexus operations

Python Nexus handlers commonly call `ctx.start_workflow(...)` from a
`@nexus.workflow_run_operation`. In the Python SDK version exercised by this
branch, that method does not expose a workflow `headers=` parameter, so Tenuo
uses an explicit workflow-input envelope plus a bootstrap helper in the
handler workflow.

Two modes are supported:

- `tenuo_forward_nexus_authority(...)` forwards the exact verified caller
  warrant/key context into the backing workflow. This is the escape hatch for
  workflows that only need to inspect caller authority, or whose worker can
  resolve the caller holder key for downstream PoP signing.
- `tenuo_create_nexus_workflow_envelope(...)` carries a handler-created,
  attenuated, or freshly minted workflow warrant. This is the preferred
  production shape: the handler verifies the Nexus operation, decides what
  internal workflow work is allowed, and passes a narrower warrant held by a
  key the handler namespace can resolve.

The backing workflow calls `tenuo_bootstrap_nexus_workflow(input.tenuo)` before
`current_warrant()`, `current_key_id()`, or `tenuo_execute_activity(...)`.

Example preferred shape:

```python
@nexus.workflow_run_operation
async def minted_refund(self, ctx, input):
    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")

    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability(
            "payment_gateway.refund",
            order_id=Exact(input.order_id),
            amount_cents=Range(0, input.amount_cents),
        )
        .ttl(3600)
        .mint(control_key)
    )
    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "handler-workflow-key",
        workflow_id=workflow_id,
        source_ctx=ctx,
        source_endpoint="billing-prod",
    )
    return await ctx.start_workflow(
        RefundWorkflow.run,
        RefundWorkflowInput(input.order_id, input.amount_cents, tenuo=envelope),
        id=workflow_id,
    )

@workflow.defn
class RefundWorkflow:
    @workflow.run
    async def run(self, input):
        tenuo_bootstrap_nexus_workflow(input.tenuo)
        return await tenuo_execute_activity(...)
```

The product goal is still the same: authorize both the incoming Nexus operation
and the work it starts.

## Phased implementation

1. **Design spike / tests**
   - Confirm exact Python SDK header behavior for Nexus caller and handler
     paths.
   - Add mocked unit tests for caller header emission and handler rejection.
   - Add one live cross-namespace allow/deny smoke test when the local
     Temporal test server supports Nexus endpoints.

2. **Sync operation support**
   - Add `tenuo_execute_nexus_operation(...)` and
     `tenuo_start_nexus_operation(...)`.
   - Add `verify_nexus_operation(...)` and `@tenuo_nexus_operation(...)`.
   - Document cross-namespace setup and denial behavior.

3. **Workflow-run operation support**
   - Add `tenuo_forward_nexus_authority(...)` for exact caller authority
     forwarding.
   - Add `tenuo_create_nexus_workflow_envelope(...)` for handler-created or
     attenuated workflow authority.
   - Add `tenuo_bootstrap_nexus_workflow(...)` so backing workflows can install
     the envelope into normal Tenuo workflow context.

4. **Production rollout guide**
   - Cover endpoint naming, namespace boundaries, revocation providers, trusted
     roots, operation naming, input normalization, retries, and observability.

## Open questions

- Should Nexus PoP bind the endpoint name only, or endpoint + resolved handler
  namespace/task queue when available?
- Should operation constraints use the service contract operation name, the
  Python handler method name, or an explicit Tenuo tool mapping?
- Should the workflow envelope grow an additional handler signature over the
  target workflow binding, or is Temporal's handler-created input boundary
  sufficient for the first experimental surface?
- What durable replay/dedup key is available for sync Nexus operations?
- Should a denied Nexus operation be represented as `UNAUTHORIZED` or as a
  Tenuo-specific non-retryable operation error with structured details?

## References

- [Temporal Nexus overview](https://docs.temporal.io/nexus)
- [Temporal Python Nexus feature guide](https://docs.temporal.io/develop/python/nexus/feature-guide)
- [Tenuo Temporal integration](./temporal.md)
