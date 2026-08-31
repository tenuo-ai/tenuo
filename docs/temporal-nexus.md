---
title: Temporal Nexus Authorization
description: Experimental Tenuo authorization across Temporal Nexus namespace boundaries
---

# Temporal Nexus Authorization

> Experimental surface. Tenuo can now emit and verify authorization headers for
> Temporal Nexus operations. Workflow-backed Nexus propagation is still a
> follow-up design area.

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
   - Add `tenuo_execute_nexus_operation(...)` and
     `tenuo_start_nexus_operation(...)`.
   - Add `verify_nexus_operation(...)` and `@tenuo_nexus_operation(...)`.
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
