---
title: Temporal Nexus Authorization
description: Tenuo authorization across Temporal Nexus namespace boundaries
---

# Temporal Nexus Authorization

> Tenuo can emit and verify authorization headers for Temporal Nexus
> operations, and can carry verified authority into workflow-backed Nexus
> operations through an explicit envelope/bootstrap path.

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
config = TenuoPluginConfig(
    ...,
    nexus_endpoint="billing-prod",
)

class BillingServiceHandler:
    @tenuo_nexus_operation(config, endpoint="billing-prod")
    async def refund(self, ctx, input: RefundInput) -> RefundOutput:
        ...
```

If the warrant only allows `order_id="ord_123"` and
`amount_cents <= 5000`, a larger or different refund is denied at the handler
boundary, even though the Nexus endpoint itself is reachable.

## Supported surfaces

### Caller workflow helper

`tenuo_execute_nexus_operation(...)` and
`tenuo_start_nexus_operation(...)` mirror the successful
`tenuo_execute_activity(...)` shape for Nexus callers:

- read the current workflow warrant, or accept a per-call `warrant=`;
- require `key_id=` when a per-call warrant is supplied;
- include the full delegated `warrant_chain`;
- optionally carry pre-collected `SignedApproval` objects with `approvals=`;
- sign proof-of-possession over Nexus-specific context; and
- pass Tenuo material through the Nexus operation `headers=` argument.

The proof input currently binds:

- endpoint name;
- service name;
- operation name;
- normalized operation input.

Tenuo-generated Nexus calls also carry diagnostic binding headers for the exact
tool name and input fields used for PoP signing. The handler compares those
headers to its own derived endpoint/service/operation and normalized input
shape before cryptographic authorization, so contract drift shows up as a
wiring error in handler logs instead of as an opaque policy denial. Manual
callers must send these headers too; missing binding headers fail closed.

`tenuo_nexus_headers(...)` is also available as a lower-level escape hatch for
advanced wiring and tests.

For approval-gated warrants, collect `SignedApproval` objects out of band and
pass them as `approvals=[...]` on the caller helper. Nexus uses the same
`x-tenuo-approvals` payload as Temporal activities: a JSON list of base64 CBOR
`SignedApproval` blobs inside the Nexus string-header envelope.

### Handler verifier

`TenuoWorkerInterceptor` authorizes inbound Nexus starts by default. Set
`TenuoPluginConfig.nexus_endpoint` to the endpoint name this worker serves.
A missing `@tenuo_nexus_operation` decorator can no longer skip authorization
on a Tenuo worker. The decorator remains useful for tests and for making the
endpoint explicit in handler source.

The handler-side surface verifies `ctx.headers` before user code runs:

- warrant chain roots, signatures, linkage, expiry, and revocation;
- PoP against the caller's holder key;
- optional strict PoP replay suppression through
  `TenuoPluginConfig.nexus_pop_replay_protection`;
- pre-supplied approval signatures for approval-gated warrants;
- service and operation binding;
- operation input constraints; and
- Nexus-native unauthorized errors via `tenuo_nexus_operation(...,
  raise_nexus_error=True)` behavior.

Authorization failures should raise Nexus-native non-retryable errors so
Temporal does not retry permanent denials.

Set `TenuoPluginConfig.nexus_endpoint` (and pass the same value as
`endpoint=` on helpers) so the signed tool string is stable. When the
installed Temporal SDK exposes the live handler endpoint, Tenuo cross-checks
it against the configured value and rejects mismatches instead of accepting
warrants scoped to the wrong endpoint. Tenuo intentionally refuses to fall
back to a placeholder endpoint because endpoint names are part of the signed
security boundary.

The supported APIs are:

- `verify_nexus_operation(ctx, input, config, ...)`
- `tenuo_nexus_operation(config, ...)`
- `nexus_tool_name(endpoint, operation, service=...)`
- `TemporalNexusOperation.exact(endpoint, operation, service=..., ...)`

Use the template helper when minting warrants so callers and handlers share the
same canonical tool string:

```python
from tenuo.templates import TemporalNexusOperation

refund_capability = TemporalNexusOperation.exact(
    "billing-prod",
    "refund",
    service="BillingService",
    order_id=Exact("ord_123"),
    amount_cents=Range(max=5000),
)
```

### Workflow-backed Nexus operations

Python Nexus handlers commonly call `ctx.start_workflow(...)` from a
`@nexus.workflow_run_operation`. Tenuo supports that shape without putting
authority into ordinary workflow input: `tenuo_start_nexus_workflow(...)`
verifies the incoming Nexus request, binds a handler-created or attenuated
workflow warrant to the exact backing `workflow_id`, then calls
`ctx.start_workflow(...)` through the normal Temporal client interceptor path.

Tenuo's client interceptor can inject headers into Nexus backing workflow
starts without dropping Nexus-specific fields such as `request_id`, callbacks,
or workflow event links; this path is covered by both focused adapter coverage
and an isolated live Nexus backing-start concurrency probe.

Three modes are supported:

- `tenuo_start_nexus_workflow(...)` carries handler-created, attenuated, or
  freshly minted workflow authority via Temporal workflow headers. This is the
  preferred production shape for backing workflows: the handler verifies the
  public Nexus operation, decides what internal workflow work is allowed, and
  starts that workflow with a narrower warrant held by a key the handler
  namespace can resolve.
- `tenuo_forward_nexus_authority(...)` forwards the exact verified caller
  warrant/key context into the backing workflow. This is the escape hatch for
  workflows that only need to inspect caller authority, or whose worker can
  resolve the caller holder key for downstream PoP signing.
- `tenuo_create_nexus_workflow_envelope(...)` carries a handler-created,
  attenuated, or freshly minted workflow warrant through explicit workflow
  input. Prefer `tenuo_start_nexus_workflow(...)` when the handler client has
  `TenuoClientInterceptor`; keep the envelope path for manual transports,
  migration, or cases where making bootstrap explicit in the workflow input is
  desirable.

The ambient helper requires the `TenuoClientInterceptor` instance installed on
the handler namespace client. After a successful `ctx.start_workflow(...)`,
Tenuo fails closed if that interceptor did not consume the pending header
binding. If start fails before consume, Tenuo discards only the matching
binding so a concurrent rebound of the same `workflow_id` stays intact.

Envelope-backed workflows call `tenuo_bootstrap_nexus_workflow(input.tenuo)`
before `current_warrant()`, `current_key_id()`, or
`tenuo_execute_activity(...)`. Both envelope constructors require
`workflow_id=` so the bootstrap step can reject replay into a different backing
workflow. Bootstrap also resolves the envelope `key_id` and requires it to
match the warrant holder key before the workflow can use that key for
downstream PoP signing.

Treat the backing workflow as an internal implementation detail of the Nexus
handler. Do not expose it for direct starts by untrusted clients; ordinary
workflow input is not a Nexus request boundary. If external clients can start
the backing workflow directly, they can bypass the Nexus operation verifier and
should instead be routed through a Nexus endpoint or an authorized workflow
start helper.

Example preferred shape:

```python
@nexus.workflow_run_operation
async def minted_refund(self, ctx, input):
    workflow_id = f"refund-{ctx.request_id}"
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

    return await tenuo_start_nexus_workflow(
        ctx,
        input,
        config,
        handler_client_interceptor,
        RefundWorkflow.run,
        RefundWorkflowInput(input.order_id, input.amount_cents),
        workflow_id=workflow_id,
        workflow_warrant=workflow_warrant,
        workflow_key_id="handler-workflow-key",
        endpoint="billing-prod",
    )

@workflow.defn
class RefundWorkflow:
    @workflow.run
    async def run(self, input):
        return await tenuo_execute_activity(...)
```

The product goal is still the same: authorize both the incoming Nexus operation
and the work it starts.

### Sync router handlers: signals, queries, and updates

Temporal's Nexus guidance also calls out a common enterprise router pattern:
a synchronous Nexus handler receives a cross-namespace request, then uses a
Temporal client handle to signal, query, or update an existing workflow. Tenuo
supports that shape with small handler-side helpers:

- `tenuo_nexus_signal_workflow(ctx, input, config, handle, signal, ...)`
- `tenuo_nexus_query_workflow(ctx, input, config, handle, query, ...)`
- `tenuo_nexus_execute_update(ctx, input, config, handle, update, ...)`
- `tenuo_nexus_start_update(ctx, input, config, handle, update, ...)`

Each helper first verifies the signed Nexus operation and input with
`verify_nexus_operation(..., raise_nexus_error=True)`. Only after that passes
does it call the corresponding Temporal `WorkflowHandle` method.

The warrant authorizes the public Nexus operation, so put the policy-relevant
routing fields in the Nexus input: target workflow id, signal/query/update
name, tenant id, record id, and any payload fields that should be constrained.
The handler may then map those verified fields to the internal Temporal handle
operation without exposing handler namespace credentials to the caller.

Example:

```python
@dataclass
class ApprovalRoute:
    workflow_id: str
    tenant_id: str
    decision: str


@nexus.sync_operation
async def approve(self, ctx, input: ApprovalRoute) -> None:
    handle = temporal_client.get_workflow_handle(input.workflow_id)
    await tenuo_nexus_signal_workflow(
        ctx,
        input,
        config,
        handle,
        ApprovalWorkflow.approve,
        input.decision,
        endpoint="approvals-prod",
    )
```

The matching warrant should constrain the Nexus route operation, for example
`nexus:approvals-prod:ApprovalService:approve` with exact `workflow_id` and
`tenant_id` fields and an allowed `decision` set.

## Enterprise examples

These examples mirror the main Nexus topologies documented by Temporal:
cross-team service contracts, isolated Namespaces, workflow-backed async
operations, and router Workers that expose safe self-service entry points.

### AI agent requests a payment action

An agent workflow in `finance-ai-prd` needs to request a refund from
`finance-payments-prd`. Temporal Cloud can allow the AI Namespace to reach the
`payments-prod` Nexus Endpoint, but the payments team still needs to know
whether this specific agent run may refund this specific order for this amount.

The caller presents a warrant for the public Nexus operation:

```python
await tenuo_execute_nexus_operation(
    nexus_client,
    PaymentService.refund,
    RefundInput(order_id="ord_123", amount_cents=5000, tenant_id="acme"),
    warrant=refund_warrant,
    key_id="finance-agent-key",
)
```

The handler verifies the Nexus request, then mints a narrower workflow warrant
held by a payments-owned key. The backing workflow can use that attenuated
authority to call internal payment activities without giving the agent
Namespace payment credentials:

```python
@nexus.workflow_run_operation
async def refund(self, ctx, input: RefundInput):
    verify_nexus_operation(ctx, input, config, endpoint="payments-prod")

    workflow_id = f"refund-{input.tenant_id}-{input.order_id}"
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(payments_workflow_key.public_key)
        .capability(
            "payment_gateway.refund",
            tenant_id=Exact(input.tenant_id),
            order_id=Exact(input.order_id),
            amount_cents=Range(0, input.amount_cents),
        )
        .ttl(900)
        .mint(payments_root_key)
    )
    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "payments-workflow-key",
        workflow_id=workflow_id,
        source_ctx=ctx,
        source_endpoint="payments-prod",
    )
    return await ctx.start_workflow(
        RefundWorkflow.run,
        RefundWorkflowInput(input, tenuo=envelope),
        id=workflow_id,
    )
```

This is the cleanest Tenuo/Nexus story: Temporal routes the durable
cross-namespace operation; Tenuo proves least-privilege authority over the
business action and its arguments.

### Developer portal routes approved infrastructure changes

A platform Namespace exposes a self-service Nexus Endpoint such as
`cloud-ops-prod`. Product teams can request operations like resizing a
service, rotating a credential, or creating an environment without direct
access to the platform Namespace.

For quick operations that map to an existing platform workflow, use the router
helper shape:

```python
@nexus.sync_operation
async def resize_service(self, ctx, input: ResizeServiceInput) -> None:
    handle = temporal_client.get_workflow_handle(input.platform_workflow_id)
    await tenuo_nexus_execute_update(
        ctx,
        input,
        config,
        handle,
        PlatformWorkflow.resize_service,
        input.service_name,
        input.target_size,
        endpoint="cloud-ops-prod",
    )
```

The warrant should constrain `tenant_id`, `service_name`, environment, and the
allowed size range. The platform team keeps ownership of the workflow and IAM
credentials, while product teams receive a durable self-service contract.

### Multi-hop service composition

Nexus allows one handler workflow to call another Nexus operation. A production
flow might look like:

```text
AgentWorkflow
  -> payments-prod:PaymentService.refund
  -> compliance-prod:ReviewService.screen_refund
  -> fulfillment-prod:FulfillmentService.release_credit
```

Each hop should attenuate authority rather than forwarding a broad original
warrant. For example, the payments handler can verify that the agent may ask
for a refund, then mint a narrower warrant allowing compliance to screen only
that refund record. After approval, payments can mint a separate warrant for
fulfillment to release only the resulting credit.

That keeps the chain auditable and prevents a warrant intended for one team or
resource from becoming ambient authority across the whole platform.

For a customer-facing walkthrough of these scenarios, including cross-team,
multi-hop, and cross-organization examples, see
[Tenuo for Temporal Nexus](./temporal-nexus-use-cases.md).

## Enterprise operating guidance

### Endpoint names are part of the security boundary

Nexus callers address endpoints by name, and Tenuo's proof-of-possession binds
that endpoint name into the signed tool string. This is intentional: a warrant
for `billing-prod` should not silently authorize a call to `billing-staging` or
to a renamed endpoint. Operationally, endpoint renames require issuing updated
warrants and draining or handling in-flight callers that still reference the
old name.

### Use workflow ids and conflict policy for async dedupe

Nexus delivery is at-least-once. Tenuo verifies authority, but replay
suppression is not enabled by default because identical repeat calls can share
the same PoP signature inside the core PoP time bucket. If you enable
`TenuoPluginConfig.nexus_pop_replay_protection=True`, Tenuo rejects a captured
PoP signature reused under a different Nexus `request_id`, while allowing the
same signature with the same `request_id` as a Temporal redelivery. Use a
shared owner-aware `pop_dedup_store` for multi-worker or multi-namespace
deployments.

Replay suppression still does not make arbitrary handler side effects
idempotent, and a captured PoP replayed with the captured `request_id` is
indistinguishable from Temporal redelivery. For workflow-backed operations,
derive a stable workflow id from the business request and use Temporal's
workflow id conflict policy to dedupe retried or duplicated Nexus starts; sync
operations need their own business idempotency if duplicate effects matter.
`tenuo_create_nexus_workflow_envelope(...)` and
`tenuo_forward_nexus_authority(...)` require `workflow_id=` so the envelope is
bound to that exact backing workflow.

### Prefer attenuation at each hop

Multi-level Nexus calls are supported by Temporal, and a bootstrapped Tenuo
workflow can make another Tenuo-authorized Nexus call. For production, prefer
minting or attenuating a narrower warrant at each hop. Forward exact caller
authority only when the next workflow genuinely needs the caller's original
holder context and the worker can resolve that holder key.

### Temporal platform controls still matter

Tenuo is an application authorization layer, not a replacement for Temporal
Cloud or cluster controls. Keep using namespace isolation, endpoint ownership,
Temporal ACLs, mTLS or Cloud identity, payload codecs/encryption, rate limits,
and observability. Tenuo answers "is this caller allowed to perform this
operation on this input?"; Temporal still controls who can create endpoints,
deploy workers, reach namespaces, and operate the cluster.

### Keep cross-SDK input contracts stable

Tenuo normalizes the decoded Nexus operation input before checking warrant
constraints. Python-to-Python callers can usually rely on dataclass or mapping
field names. Polyglot services should define explicit JSON or protobuf field
names and keep those names stable, because warrant constraints are written
against the decoded argument shape. Non-Python callers must send the same
`x-tenuo-*` headers that `tenuo_nexus_headers(...)` emits, including
`x-tenuo-tool-name` and `x-tenuo-arg-keys`.

## Production checklist

Ship a Tenuo Nexus worker only when all of these are true:

- `TenuoPluginConfig.nexus_endpoint` is set to the endpoint this worker serves.
- The worker is constructed with `TenuoWorkerInterceptor` or
  `TenuoTemporalPlugin`, so inbound Nexus starts are authorized by default.
- Backing workflow starts use `tenuo_start_nexus_workflow(...)` with the
  `TenuoClientInterceptor` instance installed on the handler client.
- Backing workflows are not startable by untrusted clients.
- `control_plane` is set, or you rely on the interceptor to attach
  `get_or_create()` to the same config object used by verify/decorators.
- `audit_callback` is set if you need in-process Temporal audit events for
  Nexus allow/deny (control-plane emission is not a substitute).
- Multi-worker fleets that enable `nexus_pop_replay_protection=True` also set
  a shared owner-aware `pop_dedup_store`. Otherwise prefer stable backing
  `workflow_id` values and Temporal conflict policy for at-least-once delivery.
- Polyglot callers share the same canonical tool string
  (`nexus:<endpoint>:<service>:<operation>`) and the same top-level input
  field names the warrant constrains.

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
   - Covered above: interceptor-default Nexus authorization, shared
     control-plane/audit wiring, ambient backing starts, endpoint naming,
     replay vs workflow-id idempotency, and polyglot header contracts.

5. **Enterprise router helpers**
   - Add first-class helpers for Nexus handlers that authorize the incoming
     request before signaling, querying, or updating an existing Temporal
     workflow.

## Open questions

- Should Nexus PoP later also bind the resolved handler namespace or task
  queue, or is the explicit endpoint name enough for this surface?
- v1 decisions already locked: tool names use
  `nexus:<endpoint>:<service>:<operation>`; ambient header starts are preferred
  over envelopes; handler denials use Nexus `UNAUTHORIZED`.

## References

- [Temporal Nexus overview](https://docs.temporal.io/nexus)
- [Temporal Python Nexus feature guide](https://docs.temporal.io/develop/python/nexus/feature-guide)
- [Tenuo for Temporal Nexus](./temporal-nexus-use-cases.md)
- [Tenuo Temporal integration](./temporal.md)
