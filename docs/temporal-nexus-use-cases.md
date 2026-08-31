---
title: Tenuo for Temporal Nexus
description: Practical examples for authorizing Temporal Nexus operations across teams, namespaces, and organizations
---

# Tenuo for Temporal Nexus

Temporal Nexus gives teams a durable way to expose capabilities across
Namespace boundaries. Tenuo adds the missing application authorization layer:
not just "can this Namespace reach this Endpoint?", but "can this specific
workflow, agent, user, or delegation perform this exact operation with these
arguments?"

That matters most when Nexus crosses a trust boundary: another team, another
environment, another business unit, or another organization.

## The value in one sentence

Temporal Nexus routes durable work across isolated Namespaces; Tenuo carries a
signed, task-scoped warrant across that boundary so the handler can verify
least-privilege authority before doing consequential work.

## What Tenuo adds to Nexus

Temporal already provides the durable platform boundary:

- isolated caller and handler Namespaces;
- named Nexus Endpoints;
- reliable delivery, retries, callbacks, and observability;
- Cloud endpoint allowlists and worker authentication.

Tenuo adds the business authorization boundary:

- signed warrants for the specific Nexus service and operation;
- input constraints such as tenant, order, amount, workflow id, path, or region;
- proof-of-possession from the warrant holder key;
- delegation chains that narrow authority at each hop;
- expiry, revocation, and optional signed human approvals;
- a way to carry verified or attenuated authority into workflow-backed handlers.

In practice, Temporal decides where the request may go. Tenuo decides whether
this request is allowed to do this thing.

## Enterprise-scale control across teams

As Nexus adoption grows, the hard part is usually not a single operation
handler. It is the operating model around many teams sharing durable
capabilities:

- Security wants one place to define who may issue authority for production
  operations.
- Platform teams want to expose self-service workflows without giving every
  caller direct cloud or database credentials.
- Service owners want revocation and key rotation without redeploying every
  worker.
- Audit and compliance teams want a queryable trail across Namespaces, business
  units, and external partners.
- Approvers need a managed path for high-risk actions that still works with
  long-running workflows.

Tenuo can be run self-hosted with your own issuer service, trusted-root
distribution, revocation-list publisher, approval service, and receipt store.
For enterprise teams that want those controls operated centrally, a managed
Tenuo control plane can provide the shared operational layer: warrant issuance,
root distribution, revocation, approvals, key rotation, and audit indexing
across the Temporal fleet.

The product boundary stays the same either way: Nexus carries the durable
cross-Namespace call, and Tenuo carries the signed, task-scoped authority. The
managed control plane is about running that authority system consistently at
enterprise scale.

If you are evaluating this model for multiple teams or business units,
[schedule a demo / request access](https://tenuo.ai/early-access.html) and we
can walk through your Temporal topology.

## Example 1: AI agent requests a payment refund

An AI workflow in `finance-ai-prd` identifies that a customer needs a refund.
The payment workflow lives in `finance-payments-prd`, owned by another team.

Without Tenuo, the payments team can allow the AI Namespace to call the
`payments-prod` Nexus Endpoint, but the handler still needs its own logic to
answer:

- Which agent is acting?
- Who authorized it?
- Which tenant and order are in scope?
- What maximum amount is allowed?
- Has the authorization expired or been revoked?
- Does this operation require human approval?

With Tenuo, the caller presents a warrant scoped to the public Nexus operation:

```python
await tenuo_execute_nexus_operation(
    nexus_client,
    PaymentService.refund,
    RefundInput(
        tenant_id="acme",
        order_id="ord_123",
        amount_cents=5000,
    ),
    warrant=refund_warrant,
    key_id="finance-agent-key",
)
```

The payments handler verifies that warrant before starting the internal refund
workflow:

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

The agent never receives payment system credentials. The payments workflow
receives only the authority it needs for this refund.

## Example 2: Developer portal for infrastructure self-service

A platform team exposes a `cloud-ops-prod` Nexus Endpoint. Product teams can
request safe infrastructure changes from their own Namespaces:

- resize a service;
- create a preview environment;
- rotate a credential;
- grant temporary access to a data export.

The platform team keeps ownership of the underlying workflows and cloud IAM
credentials. Product teams receive a durable self-service API.

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

The warrant can constrain `tenant_id`, `service_name`, `environment`, and
`target_size`. A product team can request a scale-up for its own staging
service, but not another team's production database.

## Example 3: Multi-hop business process

Enterprise workflows rarely stop at one service boundary. A refund can require
payments, compliance, fulfillment, and customer messaging.

```text
finance-ai-prd
  AgentWorkflow
    -> payments-prod:PaymentService.refund

finance-payments-prd
  RefundWorkflow
    -> compliance-prod:ReviewService.screen_refund

finance-compliance-prd
  ReviewWorkflow
    -> fulfillment-prod:FulfillmentService.release_credit

commerce-fulfillment-prd
  CreditWorkflow
```

Each Nexus hop gets a narrower warrant:

1. The agent warrant allows requesting a refund for one tenant/order/amount.
2. Payments verifies the agent request and mints a compliance warrant for only
   that refund record.
3. Compliance verifies the screening request and returns a signed decision.
4. Payments mints a fulfillment warrant for only the approved credit release.

This preserves a useful audit trail: every team can see the exact authority it
received, who delegated it, which input was authorized, and where the chain
continued.

## Example 4: Cross-organization operations

Nexus can also model business-to-business workflows where each organization
keeps its own Temporal Namespace and operational control.

Imagine a marketplace company coordinating with a logistics partner:

```text
marketplace-prd
  ReturnWorkflow
    -> logistics-partner-prod:PickupService.schedule_pickup

logistics-partner-prd
  PickupWorkflow
    -> marketplace-prod:ReturnService.confirm_label
```

The marketplace can issue a warrant allowing the partner to schedule pickup
only for:

- one merchant;
- one return id;
- one pickup window;
- one destination facility;
- a short TTL.

The logistics partner can verify the warrant without receiving broader access
to marketplace systems. If the partner later calls back through another Nexus
Endpoint, it presents a separate warrant for that callback operation.

This is where Tenuo's portability matters: the authorization artifact is a
signed warrant chain, not an ambient credential or a shared database lookup.

## Example 5: Approval-gated Nexus operations

Some Nexus operations should require human approval even if the caller has a
valid warrant:

- refunds over a threshold;
- production infrastructure changes;
- access to regulated datasets;
- external vendor actions.

The caller collects signed approvals and sends them with the Nexus operation:

```python
await tenuo_execute_nexus_operation(
    nexus_client,
    PaymentService.refund,
    RefundInput(order_id="ord_123", amount_cents=250000),
    warrant=refund_warrant,
    key_id="finance-agent-key",
    approvals=[finance_manager_approval, risk_approval],
)
```

The handler verifies the warrant and approval signatures before the operation
continues. If approvals are missing or insufficient, the denial is explicit and
non-retryable; the workflow can collect the required signatures and retry with
the same business idempotency key.

## Operational model

Use Tenuo with Temporal's existing controls, not instead of them.

| Layer | What it controls |
|---|---|
| Temporal Namespace isolation | Which workers and workflows are isolated from each other |
| Temporal Nexus Endpoint ACLs | Which caller Namespaces may reach an Endpoint |
| Worker identity / mTLS / API keys | Which deployed workers and clients can connect |
| Payload codec / encryption | Who can read operation inputs and results |
| Tenuo warrants | Which actor/delegation may perform which operation with which input |
| Tenuo approvals and revocation | Who can approve sensitive actions and how authority is stopped |

For workflow-backed Nexus operations, prefer handler-minted or attenuated
workflow warrants. Forward the caller's exact warrant only when the backing
workflow genuinely needs the caller's original holder context.

## Do we need a managed control plane?

Not for every deployment. A single team can start with local keys, a small
issuer service, static trusted roots, and self-hosted audit storage.

Consider a managed control plane when the authorization boundary spans multiple
teams, Namespaces, accounts, or organizations and you need centralized control
over:

- which systems may mint production warrants;
- how trust roots and holder keys rotate;
- how revocations reach every worker;
- how human approvals are routed and recorded;
- how auditors search receipts across workflows and partners.

That is the point where the problem shifts from "can this handler verify a
warrant?" to "can the enterprise operate warrant authority safely across all
the teams using Nexus?"

For that enterprise-scale operating model,
[schedule a demo / request access](https://tenuo.ai/early-access.html).

## When this is the right fit

Tenuo for Nexus is strongest when:

- multiple teams share a Temporal platform but own separate Namespaces;
- AI agents need to invoke workflows owned by high-trust teams;
- platform teams expose self-service workflows without handing out broad IAM;
- operations cross production/staging or tenant boundaries;
- a durable workflow call needs business-level authorization, approvals, and
  auditability.

If one team owns both sides and the operation is low risk, Temporal's built-in
Namespace and Endpoint controls may be enough. Add Tenuo when the operation's
arguments and delegation chain matter.

## Learn more

- [Temporal Integration](./temporal.md)
- [Temporal Nexus Authorization](./temporal-nexus.md)
- [Temporal Integration Reference](./temporal-reference.md)
