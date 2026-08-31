---
title: Temporal Nexus Authorization
description: Design preview for Tenuo authorization across Temporal Nexus namespace boundaries
---

# Temporal Nexus Authorization

> Design preview. This page sketches the product and implementation shape for
> Tenuo support across Temporal Nexus endpoints.

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
nexus_client = tenuo_nexus_client(
    service=BillingService,
    endpoint="billing-prod",
)

await nexus_client.execute_operation(
    BillingService.refund,
    RefundInput(order_id="ord_123", amount_cents=5000),
    warrant=refund_warrant,
    key_id="agent-key",
)
```

The `billing-namespace` handler verifies the Tenuo warrant before performing
the refund:

```python
@tenuo_nexus_service(config)
class BillingServiceHandler:
    @tenuo_nexus_operation("refund")
    async def refund(self, ctx, input: RefundInput) -> RefundOutput:
        ...
```

If the warrant only allows `order_id="ord_123"` and
`amount_cents <= 5000`, a larger or different refund is denied at the handler
boundary, even though the Nexus endpoint itself is reachable.

## Proposed surfaces

### Caller workflow helper

`tenuo_execute_nexus_operation(...)` should mirror the successful
`tenuo_execute_activity(...)` shape:

- read the current workflow warrant, or accept a per-call `warrant=`;
- require `key_id=` when a per-call warrant is supplied;
- include the full delegated `warrant_chain`;
- sign proof-of-possession over Nexus-specific context; and
- pass Tenuo material through the Nexus operation `headers=` argument.

The proof input should bind at least:

- endpoint name;
- service name;
- operation name;
- normalized operation input; and
- workflow identity / run identity when available.

### Handler verifier

The handler-side surface should verify `ctx.headers` before user code runs:

- warrant chain roots, signatures, linkage, expiry, and revocation;
- PoP against the caller's holder key;
- service and operation binding;
- operation input constraints; and
- replay/dedup where Nexus task metadata makes that possible.

Authorization failures should raise Nexus-native non-retryable errors so
Temporal does not retry permanent denials.

### Workflow-backed Nexus operations

Workflow-backed Nexus operations need one extra design decision. Python Nexus
handlers commonly call `ctx.start_workflow(...)` from a
`@nexus.workflow_run_operation`. If the SDK exposes workflow headers for that
start path, Tenuo should propagate the verified Tenuo context into the handler
workflow headers. If not, Tenuo needs an explicit signed envelope in workflow
input, plus a bootstrap helper in the handler workflow.

The product goal is still the same: authorize both the incoming Nexus operation
and the work it starts.

## Phased implementation

1. **Design spike / tests**
   - Confirm exact Python SDK header behavior for Nexus caller and handler
     paths.
   - Add mocked unit tests for caller header emission and handler rejection.
   - Add one live cross-namespace sample if the Temporal test server supports
     Nexus endpoints in CI.

2. **Sync operation support**
   - Add `tenuo_execute_nexus_operation(...)`.
   - Add `@tenuo_nexus_service` / `@tenuo_nexus_operation` or an equivalent
     service-handler wrapper.
   - Document cross-namespace setup and denial behavior.

3. **Workflow-run operation support**
   - Propagate verified authority into handler workflows through SDK workflow
     headers if possible.
   - Otherwise, design a signed workflow-input envelope and explicit workflow
     bootstrap helper.

4. **Production rollout guide**
   - Cover endpoint naming, namespace boundaries, revocation providers, trusted
     roots, operation naming, input normalization, retries, and observability.

## Open questions

- Should Nexus PoP bind the endpoint name only, or endpoint + resolved handler
  namespace/task queue when available?
- Should operation constraints use the service contract operation name, the
  Python handler method name, or an explicit Tenuo tool mapping?
- Can Temporal's Python SDK pass workflow headers from
  `WorkflowRunOperationContext.start_workflow(...)` today?
- What durable replay/dedup key is available for sync Nexus operations?
- Should a denied Nexus operation be represented as `UNAUTHORIZED` or as a
  Tenuo-specific non-retryable operation error with structured details?

## References

- [Temporal Nexus overview](https://docs.temporal.io/nexus)
- [Temporal Python Nexus feature guide](https://docs.temporal.io/develop/python/nexus/feature-guide)
- [Tenuo Temporal integration](./temporal.md)
