---
title: "Task-scoped authorization for durable AI workflows"
description: "How Tenuo and Temporal combine durable execution with task-scoped cryptographic authorization."
layout: default
permalink: /blog/temporal-partnership.html
canonical_url: https://tenuo.ai/blog/temporal-partnership.html
og_image: /images/og-temporal-partnership.png
author: "Niki Aimable Niyikiza"
date: 2026-05-27
tags: ["Temporal", "AI agents", "authorization", "security"]
---

# Task-scoped authorization for durable AI workflows

<div class="partner-lockup">
  <img src="/images/integrations/temporal-logo-horizontal-light.png" alt="Temporal" class="no-zoom partner-logo-temporal" />
  <span class="partner-separator">×</span>
  <img src="/images/tenuo-logo.png" alt="Tenuo" class="no-zoom partner-logo-tenuo" />
</div>

If you're running AI agents in production, you've probably bumped into two of the hardest things to get right: how do you keep them alive across crashes, and how do you keep them on a leash even when they are hallucinating or prompt-injected? [Temporal](https://temporal.io) solves the first. [Tenuo](https://tenuo.ai/) solves the second, and the two now have an official integration, with Tenuo now part of Temporal's [AI Partner Ecosystem](https://temporal.io/partners/ai). You get cryptographic authorization for every tool call, with no changes to your existing Activity code.

> [!NOTE]
> Tenuo is part of Temporal's [AI Partner Ecosystem](https://temporal.io/partners/ai), and this post shows how the integration works in a real agentic incident-response flow.

We'll get to the code in a minute. First, a look at why the integration takes the shape it does.

## A natural pairing

Running agents on Temporal already gets you something most agent stacks don't. Workflows survive crashes, replay deterministically, run for hours without dropping state. Durable execution is solved.

Around that durable execution sits the rest of the deployment. A worker runs with a service account or OAuth token scoped broadly enough to call every Activity it's registered to handle. For static workloads that's the right model: the call graph is fixed at deploy time, the credential is evaluated once.

Agents change this picture. The call graph isn't fixed at deploy time; the AI model picks the calls at runtime. A worker with credentials broad enough to call the customer database, the payment API, and the file system authorizes the agent to use all three at any moment, regardless of what the current task requires. If the agent calls `process_refund` to send $50,000 to an unfamiliar account, the worker's payment API credential processes it: the amount and recipient were runtime decisions the credential wasn't issued to constrain.

Sub-agents inherit the same problem. The parent can pass narrower instructions to a child workflow, but nothing at the worker boundary enforces them. The child runs with whatever credentials its worker holds, typically broader than any single sub-task needs.

Durability sharpens the problem. An agent loop that pauses on a signal, resumes after a worker restart, and decides between dozens of tool calls inside a single workflow carries those broad credentials through every decision. The more decisions the agent makes under one set of credentials, the more per-task scoping matters.

Tenuo addresses this challenge with a task-scoped warrant: a cryptographic authorization layer that operates on top of your worker's existing credentials (service account or OAuth token) and is verified offline at the worker boundary before any Activity runs.

This separate layer bounds a prompt-injected agent's actions, gates high-risk calls on cryptographically signed human approvals, and produces an attested receipt for every single action taken.

This is achieved without touching your existing Activity code by leveraging Temporal primitives you already understand: interceptors enforce warrants, signals carry approvals, and event history provides a verifiable audit log.

## Demo: On-call AI agent

Imagine an AI agent is authorized for diagnostics (`read_logs`), but a task-scoped warrant enforces a human-in-the-loop approval gate (`approval_gate`) for high-risk actions like restarting a production service. A PagerDuty-style alert fires for high error rate on `payment-service-prod`. The workflow starts with an incident-scoped warrant, and the agent loop runs:

```
[tool ✓]   read_logs                 ALLOWED
[tool ✓]   read_metrics              ALLOWED
[tool ✓]   read_metrics              ALLOWED
[gate]     restart_service           approval_gate triggered (warrant requires HITL)
[hitl]     awaiting human approval   http://localhost:5050/approvals/IR-…-001
```

The workflow waits, durably, on a Temporal signal. The on-call lead opens the approval UI in their browser, sees a card describing the request, and clicks "Sign and approve." The UI signs an `ApprovalPayload` with their Ed25519 key.

The workflow receives the signal, attaches the approval to the next dispatch via Tenuo's `set_activity_approvals(...)`, and the activity inbound runs `tenuo_core.verify_approvals`.

Verification applies three checks: signature validity, request-hash binding, and approver pubkey membership in the warrant's `required_approvers`.

```
[hitl ✓]   approval IR-…-001 granted by operator
[tool ✓]   restart_service           ALLOWED (signed approval verified)
[tool ✓]   post_status               ALLOWED
[done]     workflow complete
```

End-of-incident receipt chain:

```
incident-warrant
  ├── read_logs                 ALLOWED
  ├── read_metrics              ALLOWED  ×2
  ├── restart_service           GATE    (warrant requires HITL)
  ├── approval-requested
  ├── approval-granted          (Ed25519-signed by oncall-lead)
  ├── restart_service           ALLOWED  (signed approval verified)
  ├── post_status               ALLOWED
  └── (workflow complete)
```

That's the audit chain a regulator wants to see.

The warrant is issuer-signed, each dispatch carries the holder's PoP signature, and every elevated action carries the operator's SignedApproval. Each entry becomes an independently attested cryptographic receipt.

The whole chain verifies offline with just a trusted-root pubkey. Temporal's event history is immutable and replayable, so every decision in the sequence can be reconstructed, not just recalled from logs. Every ALLOWED is provably tied to the provenance of authority.

Quick term notes:
- `PoP` (Proof of Possession): each tool call must be signed by the holder key named in the warrant, so a stolen warrant by itself is unusable.
- `SignedApproval`: a human approver's cryptographic signature over one gated request.
- `Attenuated warrant`: a child warrant with fewer permissions than its parent.

## Adding it to your worker

The integration plugs in at two points. Neither requires Activity code changes, and verification happens entirely at the worker, with no call to a central server.

![Conceptual diagram showing how warrants enforce authorization.](/images/temporal_image1.png)
{: .blog-image}

Conceptual Diagram: How Warrants Enforce Authorization.
{: .image-caption}

**1\. Add the plugin.** One config object, one line on `Client.connect`:

```py
from tenuo.temporal import (
    EnvKeyResolver, TenuoPluginConfig, TenuoTemporalPlugin,
)

plugin = TenuoTemporalPlugin(TenuoPluginConfig(
    key_resolver=EnvKeyResolver(),
    trusted_roots=[org_root.public_key],
    activity_fns=[read_logs, read_metrics, restart_service, post_status, escalate],
))
client = await Client.connect("localhost:7233", plugins=[plugin])
```

`activity_fns` is the same list you pass to `Worker(activities=[...])`. The interceptors use it to bind PoP signatures to real argument names like `name=` and `environment=` rather than positional placeholders.

**2\. Mint a task-scoped warrant.** Per-incident, with TTL matched to your SLA, capability constraints matched to the agent's intended scope, and `approval_gates` for elevated actions:

```py
from tenuo import Warrant, Wildcard, Exact, OneOf

warrant = (Warrant.mint_builder()
    .capability("read_logs",       service=Wildcard(), window=Wildcard())
    .capability("read_metrics",    service=Wildcard(), metric=Wildcard(),
                                   window=Wildcard())
    .capability("restart_service", name=Wildcard(), environment=Wildcard())
    .capability("post_status",     channel=OneOf(["#sre-alerts"]),
                                   message=Wildcard())
    .capability("escalate",        issue=Wildcard(),
                                   level=OneOf(["low", "medium"]))
    .required_approvers([oncall_lead_key.public_key])
    .approval_gates({
        "restart_service": {"environment": Exact("production")},
    })
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(oncall_lead_key))
```

For workflows that spawn sub-agents, `tenuo_execute_child_workflow` issues each child an attenuated warrant: narrower than the parent's, verifiable back to a trusted root.

## See it in the Temporal Web UI

Every authorized Activity gets a human-readable summary in the Event History:

![Temporal event history with Tenuo warrants.](/images/temporal_image2.png)
{: .blog-image}

Temporal Event History with Tenuo Warrants.
{: .image-caption}

Approvals are displayed with their cryptographic signatures. Denials show up as non-retryable `ApplicationError` events with stable error codes `(CHAIN_INVALID, WARRANT_EXPIRED, POP_VERIFICATION_FAILED, CONSTRAINT_VIOLATED`). Alerts and dashboards live on the same primitives Temporal users already use.

## From demo to production

Moving from our open-source Python demo to a production enterprise environment requires satisfying security, operations, and audit needs. This is where [Tenuo Cloud](https://tenuo.ai/early-access.html) comes in. An enterprise or regulated deployment involves more people in each warrant: security writes the policy, ops reviews approvals across timezones, audit queries the chain months later, and often requires compliance like FIPS or FedRAMP rules demanding HSM custody for the keys. Tenuo Cloud provides each role with a specialized surface: a UI for warrant authoring, approvals routed to Slack and mobile with SSO-backed identity, a queryable audit log, HSM-backed key custody, and rotation without redeploys.

## Try it

```shell
pip install "tenuo[temporal]"
```

The demo is in the [tenuo-ai/tenuo-demos](https://github.com/tenuo-ai/tenuo-demos) repository:

```shell
git clone https://github.com/tenuo-ai/tenuo-demos
cd tenuo-demos/temporal-incident-response
temporal server start-dev      # in a separate terminal
make setup
make demo
```

In about 5 minutes, you'll see:
- a gated `restart_service` action pause on human approval,
- a signed approval unblocking the workflow,
- an auditable event history showing who approved what and why.

`make demo` starts the workflow and the approval UI together. When the agent hits the production-restart gate, open [http://localhost:5050](http://localhost:5050) and click **Sign and approve**; the workflow verifies the signed approval and continues. For a hands-off run, use `make demo-auto`.

- [Tenuo \+ Temporal integration guide](https://tenuo.ai/temporal)
- [Temporal incident demo source on GitHub](https://github.com/tenuo-ai/tenuo-demos/tree/main/temporal-incident-response)
