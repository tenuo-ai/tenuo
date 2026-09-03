---
title: "Per-request authorization for Temporal Nexus"
description: "Nexus allowlists decide whether a namespace may reach an endpoint. They cannot evaluate the request. Here is how task-scoped warrants close that gap without changing service contracts."
layout: default
permalink: /blog/temporal-nexus-authorization.html
canonical_url: https://tenuo.ai/blog/temporal-nexus-authorization.html
og_image: /images/og-temporal-nexus-authorization.png
og_image_alt: "Per-request authorization for Temporal Nexus — task-scoped authority across namespace boundaries"
author: "Niki Aimable Niyikiza"
date: 2026-09-03
tags: ["Temporal", "Nexus", "authorization", "AI agents"]
---

# Per-request authorization for Temporal Nexus

*Carrying task-scoped authority across namespace boundaries*

> **TL;DR:** Nexus endpoint allowlists and worker IAM are essential, but they operate at the namespace and worker-identity level; they cannot evaluate the specific request. Tenuo bridges this gap by attaching cryptographically verified warrants to Nexus requests, allowing handlers to enforce authorization based on operation arguments, delegation chains, and expirations, all without added network latency. Existing infrastructure remains untouched.

[Temporal Nexus](https://docs.temporal.io/nexus) makes cross-team integration much easier. One team publishes a service contract, another team calls it, and Temporal makes the handoff durable. Infrastructure that previously required a custom API, webhook receiver, and retry queue can become a typed operation call between namespaces.

Platform engineering teams are already building on this model. [Netflix](https://pages.temporal.io/webinar-connect-applications-with-nexus.html) has described adopting Nexus to connect cloud operations for Spinnaker with control planes for real-time data systems and CDNs. [Duolingo](https://temporal.io/resources/case-studies/duolingo-temporal-nexus) built a self-service platform where Cloud Operations and more than six other teams have shipped over twenty workflows. [Miro](https://temporal.io/resources/on-demand/connect-temporal-apps-across-isolated-namespaces-with-nexus) uses Nexus to orchestrate cross-region data migration across isolated environments with no entry points for remote execution.

Nexus is also a natural boundary for agentic workflows. An agent can invoke a durable workflow as a tool, delegate work to a specialist agent owned by another team, or start an operation that continues after the model turn ends. In each case, the request may carry authority delegated by a user, another agent, or an upstream workflow.

Namespace identity tells the handler where that request came from. It does not tell the handler why the agent is authorized to make it, which limits came with the task, or whether those limits survived the handoff.

> Temporal can decide whether Product Team A may reach the platform endpoint. Something still needs to decide whether this particular task may scale **cluster-gpu-dev-a** to at most ten nodes.

## What Nexus controls, and what remains application-specific

When a Nexus request crosses namespaces, platform teams rely on three established controls.

**Endpoint access policies.** [Temporal Cloud](https://docs.temporal.io/nexus/security) verifies that the caller namespace appears in the endpoint's allowlist before routing the request to its handler. Temporal acts as the trusted broker between namespaces within a Cloud Account.

**Worker IAM.** Worker process roles determine what a worker can physically reach. A worker responsible for resizing RDS clusters should not also be able to delete AWS accounts or modify unrelated infrastructure.

**Approval steps in workflow code.** Sensitive workflows can pause until an operator approves them through a durable signal.

These controls determine whether a namespace may reach an endpoint, what infrastructure the worker may access, and whether a workflow should pause for a human decision. They do not express the authority carried by a particular request.

If Product Team A's namespace is allowlisted for a platform endpoint, Temporal permits requests from that namespace. The endpoint access policy does not evaluate application-specific limits inside each operation input.

A routine request to add five nodes to a development cluster and an out-of-scope request to add five hundred nodes to a production cluster can therefore have:

- the same caller namespace;
- the same Nexus operation;
- the same destination worker; and
- the same worker IAM credentials.

> The missing decision belongs at the handler boundary, after Temporal admits the caller and before the worker uses its credentials.

Self-hosted Temporal deployments can also implement custom cluster Authorizers. Those remain useful for cluster-level access decisions. Request-carried authority addresses a different problem: preserving application-specific limits as work moves between workflows, services, and administrative domains.

These platform controls solve for reachability, but agentic delegation shifts the problem from *where* a request comes from to *what* it is attempting to do.

## Agentic workflows turn service calls into delegation

In a conventional workflow, the team writing the caller usually determines which operation will execute. In an agentic workflow, the model may select the operation, construct its arguments, and delegate part of the task to another agent or workflow.

The Nexus call is therefore not merely service-to-service communication. It may be one step in a delegation chain that began with a user and crossed several execution environments before reaching the handler.

> A prompt injection, planning error, or incorrect tool output can change an operation's arguments without changing the caller namespace, Nexus operation, or worker credentials. The established controls still admit the request.

Application code can validate those arguments, but implementing authorization independently in every caller and handler creates two problems:

1. The receiving namespace cannot verify that an upstream validation actually ran.
2. The same policy becomes duplicated across callers, handlers, and workflow implementations.

Request authorization should live at a shared execution boundary. In Temporal, that boundary is the worker interceptor immediately before the Nexus handler executes.

## Where request-bound authority earns its place

Per-request authorization is not necessary for every Nexus operation.

A reconciliation namespace may call **run\_nightly\_close** once per day. It has one caller, one fixed operation, no request arguments that change the blast radius, and no delegation across security domains.

For that workflow, an endpoint allowlist and scoped worker IAM may be entirely sufficient. Adding keys and warrants would introduce complexity without producing a meaningful security boundary.

The case changes when the request itself determines what should be allowed.

### Argument-bound operations

A platform endpoint exposes **scale\_cluster\_pool**. Several product teams may call it, but each team should be limited to particular clusters and scaling thresholds.

A Tenuo warrant can express that limit directly:

```py
from tenuo import Warrant, Exact, Range
from tenuo.temporal import nexus_tool_name

warrant = (
    Warrant.mint_builder()
    .holder(product_team_key.public_key)
    .capability(
        nexus_tool_name(
            "cluster-ops-prod",
            "scale_cluster_pool",
            service="PlatformService",
        ),
        cluster_id=Exact("cluster-gpu-dev-a"),
        max_nodes=Range(1, 10),
    )
    .ttl(900)
    .mint(platform_root_key)
)
```

The platform team now enforces its boundary at the destination worker. A request for five nodes and one for five hundred can arrive as the same operation from the same namespace; the arguments are where their authority differs.

### Approvals bound to exact values

Suppose a scaling request above ten nodes requires approval.

A conventional approval step records that a workflow may continue. Unless the reviewed values are explicitly bound to the decision, that approval may not prove which cluster, limit, or operation the person reviewed.

Tenuo approvals bind the approver's signature to a request hash derived from the warrant, operation, holder, and normalized arguments.

An approval for:

```
cluster_id = cluster-gpu-dev-a
max_nodes  = 25
```

cannot be replayed against:

```
cluster_id = cluster-prod-core
max_nodes  = 100
```

The approval signature will not match the modified request.

With signed receipt emission configured, the organization also receives a tamper-evident record of the authorization decision and the approval presented with it.

### Different security domains

Different namespaces may belong to an acquired subsidiary, a regulated business unit, an outsourced operations team, or another group with its own keys and administrators.

Within Temporal Cloud, those namespaces still need to share a Cloud Account and satisfy the endpoint access policy. The handler separately chooses which warrant issuers it trusts, then verifies narrowly scoped requests from those domains against roots it controls.

### Multi-hop delegation

A self-service infrastructure request might cross several boundaries:

```
Engineer
  → Self-service portal / Operations agent
  → Specialist remediation agent
  → Shared workflow
  → Nexus operation
  → Backing workflow
  → Cloud activity
```

The Nexus endpoint allowlist sees the namespace making the immediate call. It does not reveal the user who initiated the task, the limits originally granted, or whether an intermediate agent widened them.

A warrant can carry those limits forward. At a delegation boundary, the current holder can create a child warrant for the next component:

```py
next_warrant = (
    current_warrant.grant_builder()
    .holder(next_service_key.public_key)
    .capability(
        nexus_tool_name(
            "compliance-prod",
            "screen_change",
            service="ReviewService",
        ),
        change_id=Exact(change_id),
    )
    .ttl(600)
    .grant(current_holder_key)
)
```

> Attenuation is monotonic. The child can retain or narrow capabilities already present in its parent, but it cannot add a new capability, widen an argument constraint, or outlive the parent.

Sometimes one security domain needs to translate an incoming request into a different internal capability. For example, a public **scale\_cluster\_pool** operation may cause an internal **update\_autoscaling\_group** activity.

That is not attenuation if the internal capability was not present in the incoming warrant. The handler verifies the incoming request and then issues a separate internal warrant under its own root. Signed receipts can link the incoming decision to the downstream issuance.

The distinction matters:

- **Attenuation** preserves one cryptographic delegation chain and proves that authority never widened.
- **New issuance** represents a new authorization decision made by the receiving domain.

Both patterns are useful, but they make different trust claims.

<figure class="diagram-figure">
  <picture>
    <source media="(max-width: 720px)" srcset="/images/temporal-nexus-request-boundary-mobile.svg">
    <img src="/images/temporal-nexus-request-boundary.svg" alt="A workflow or agent in Product Team A's namespace calls scale_cluster_pool. Temporal Cloud admits the caller namespace, the Nexus handler verifies the warrant against the operation and arguments, a destination workflow receives narrowed or newly issued authority, and the activity worker checks the activity before worker IAM reaches infrastructure." width="680" height="490" loading="lazy">
  </picture>
</figure>

Reachability, request authorization, and worker IAM are separate decisions. The handler verifies the Nexus request, then starts a backing workflow with narrowed or newly issued authority.
{: .image-caption}

## Choosing the appropriate control

| Situation | Reach for |
| :---- | :---- |
| Fixed caller, fixed operation, no risky arguments | Endpoint allowlist and worker IAM |
| Bounding what a process/activity can physically reach | Worker IAM |
| One worker serving many requesters | Warrant with argument constraints |
| Argument values determine the blast radius | Warrant with argument constraints |
| Approval must bind to exact values | Request-bound signed approval |
| Caller belongs to another security domain | Warrant with handler-controlled trusted roots |
| Regulated boundary needing decision evidence | Warrant plus signed receipt emission |
| Authority remains within one delegation chain | Attenuated child warrants |
| Receiving domain makes a new authorization decision | Newly issued local warrant plus linked evidence |

## Enforcing authority through Temporal interceptors

Tenuo integrates with the standard Temporal execution pipeline.

The Nexus request metadata carries:

- a compact CBOR-serialized warrant in **x-tenuo-warrant**;
- the warrant chain, when delegation is present;
- the holder key identifier;
- a proof-of-possession signature over the operation and normalized input; and
- any request-bound approval signatures.

The application's service contract does not change.

<figure class="diagram-figure">
  <picture>
    <source media="(max-width: 720px)" srcset="/images/temporal-nexus-cryptographic-verification-mobile.svg">
    <img src="/images/temporal-nexus-cryptographic-verification.svg" alt="The caller canonicalizes the endpoint, service, operation, and input, signs a proof of possession, and attaches the warrant chain and optional approvals as Nexus metadata. The Tenuo interceptor verifies the chain, request binding, and constraints locally, then either dispatches the handler or returns a non-retryable error." width="680" height="465" loading="lazy">
  </picture>
</figure>

The caller signs the exact operation and input. The interceptor verifies the chain, proof of possession, and constraints locally before the handler runs.
{: .image-caption}

Verification happens locally with no authorization-server call in the request path.

The Rust authorization core runs in tens of microseconds in isolated benchmarks. The complete Nexus path also includes Python and Temporal SDK processing, so production teams should measure end-to-end overhead in their own environment.

If verification fails, the interceptor returns a typed, non-retryable Nexus authorization error before the handler body executes.

Requests within the warrant proceed normally:

```
[nexus ✓] scale_cluster_pool
          cluster_id=cluster-gpu-dev-a
          max_nodes=5
          ALLOWED
```

Requests outside it fail at the worker boundary:

```
[nexus ✗] scale_cluster_pool
          cluster_id=cluster-prod-core
          max_nodes=5
          DENIED
          constraint: expected cluster-gpu-dev-a
```

```
[nexus ✗] scale_cluster_pool
          cluster_id=cluster-gpu-dev-a
          max_nodes=500
          DENIED
          constraint: max_nodes outside Range(1, 10)
```

## Integrating without changing service contracts

The Nexus service definition remains standard Temporal Python:

```py
@nexusrpc.service
class PlatformService:
    scale_cluster_pool: nexusrpc.Operation[ScaleRequest, ScaleResult]
```

The caller uses the Tenuo execution helper:

```diff
- result = await nexus_client.execute_operation(
+ result = await tenuo_execute_nexus_operation(
+     nexus_client,
      PlatformService.scale_cluster_pool,
      ScaleRequest(
          cluster_id="cluster-gpu-dev-a",
          max_nodes=5,
      ),
      schedule_to_close_timeout=timedelta(seconds=30),
  )
```

The helper reads the active warrant context, signs the normalized Nexus request, and attaches the required headers.

On the handler side, configure the endpoint and register the Temporal plugin on the client:

```py
from temporalio.client import Client
from tenuo.temporal import TenuoPluginConfig, TenuoTemporalPlugin

config = TenuoPluginConfig(
    key_resolver=vault_resolver,
    trusted_roots=[platform_root_key.public_key],
    nexus_endpoint="cluster-ops-prod",
)

plugin = TenuoTemporalPlugin(config)

client = await Client.connect(
    "localhost:7233",
    namespace="platform-operations",
    plugins=[plugin],
)
```

Workers created from that client inherit the plugin:

```py
worker = Worker(
    client,
    task_queue="platform-tq",
    workflows=[ProvisioningWorkflow],
    nexus_service_handlers=[PlatformServiceHandler()],
)
```

The worker interceptor verifies every inbound Nexus start before dispatching it to the service handler. The handler signature and business logic remain unchanged:

```py
@nexus_handler.sync_operation
async def scale_cluster_pool(
    self,
    ctx: nexus_handler.StartOperationContext,
    input: ScaleRequest,
) -> ScaleResult:
    return await execute_scaling(input)
```

Many production Nexus operations start a backing workflow rather than completing inline. After the interceptor admits the request, `tenuo_start_nexus_workflow` verifies it again at the handler, binds a handler-created or attenuated warrant to the backing `workflow_id`, and starts that workflow through the normal Temporal client path:

```py
@nexus.workflow_run_operation
async def scale_cluster_pool(self, ctx, input: ScaleRequest):
    return await tenuo_start_nexus_workflow(
        ctx,
        input,
        config,
        handler_client_interceptor,
        ProvisioningWorkflow.run,
        input,
        workflow_id=f"scale-{input.cluster_id}-{ctx.request_id}",
        workflow_warrant=internal_warrant,
        workflow_key_id="platform-handler",
    )
```

That is the path in the first diagram: the public Nexus operation is verified, then the destination workflow runs under authority the handler namespace issued or narrowed. The [Temporal Nexus authorization guide](https://tenuo.ai/temporal-nexus) covers the envelope and forwarding variants.

Teams that want the authorization boundary visible in the handler source can also add the optional decorator:

```py
@nexus_handler.sync_operation
@tenuo_nexus_operation(config, endpoint="cluster-ops-prod")
async def scale_cluster_pool(
    self,
    ctx: nexus_handler.StartOperationContext,
    input: ScaleRequest,
) -> ScaleResult:
    return await execute_scaling(input)
```

The interceptor remains the default enforcement mechanism. The decorator makes the boundary explicit and is useful for focused handler tests.

## After the Nexus hop

The Nexus handler is the cross-namespace boundary. After that, the same authority can travel with the work.

When a handler starts a backing workflow, or that workflow calls an activity, Tenuo propagates the current warrant in Temporal headers, signs outbound calls, and verifies them at the receiving worker. Standard activity calls stay unchanged:

```py
await workflow.execute_activity(
    apply_parameter_group,
    args=["prod-learner-03", "db.r6g.2xlarge"],
    start_to_close_timeout=timedelta(seconds=30),
)
```

The worker plugin verifies that the active warrant permits the target activity and arguments before execution. Downstream teams can issue child warrants to tighten limits; they cannot widen them.

## Managing authorization at scale

A platform team running dozens of workflows across multiple teams does not need authorization logic in every workflow. The plugin already carries authority through Temporal. Tenuo Cloud is how that authority gets authored, issued, and updated without putting minting code in each caller.

**Observe the real paths.** Run workers in Tenuo Cloud observe mode to record the operations and arguments that actually appear across execution paths. Policy starts from that map, not from a guess about what a workflow might call.

**Author a template once.** From observed paths, generate a policy template in the console, from a natural-language prompt, or from an MCP or OpenAPI schema. A single cluster-resize template can cover every team that calls `scale_cluster_pool`.

**Issue when work starts.** Attach a trigger to a CI/CD event or an API call so Cloud mints a scoped warrant as the task begins. Callers do not mint by hand. Downstream teams can still issue child warrants that tighten those limits; they cannot widen them.

**Change the template, not the workers.** Updating a scaling limit means updating the template. The next warrants Cloud issues carry the new bound. Workers keep verifying locally against whatever warrant arrives, so the change does not require a code change or a worker redeploy. Workflows already in flight keep the authority they were issued until those warrants expire or are revoked.

Developers still name the work class at entry points and set narrower scopes at delegation boundaries. Cloud and the SDK handle signing, chain construction, and subset checks.

## Operational boundaries

Request-bound authority adds a new authorization layer. It does not replace the controls already in place.

Keep using:

- namespace isolation and Nexus endpoint access policies;
- mTLS or Temporal Cloud API keys;
- scoped worker IAM;
- payload codecs and encryption;
- stable workflow IDs, conflict policies, and application-level idempotency;
- rate limits and cancellation semantics; and
- monitoring and alerting.

> Nexus decides whether a namespace may reach an endpoint. Worker IAM limits what the handler process can reach. Tenuo decides whether the exact operation and arguments are permitted under the authority presented with this request.

Warrants do not replace Temporal's execution guarantees. Expiry and revocation govern future protected actions, cancellation stops running work, and workflow IDs and application-level idempotency protect against duplicate execution. Replay remains Temporal's: warrants travel in history headers, and verification is deterministic so a replayed task produces the same decision.

Together, these layers create a narrower trust boundary for agentic workflows. Teams can move agents beyond recommendations and into execution without granting them authority beyond the task at hand.

## Get started

```shell
pip install 'tenuo[temporal]'
```

The [Temporal Nexus authorization guide](https://tenuo.ai/temporal-nexus) covers cross-namespace endpoint setup, workflow-backed operations, delegation, replay handling, signed receipts, and production deployment considerations. The broader [Temporal integration guide](https://tenuo.ai/temporal) covers worker setup, activities, and child-workflow delegation.

Tenuo Cloud is the control plane for that rollout: observe mode, templates, triggers, key management and rotation, signed revocation, and authorization evidence across namespaces and trust domains.

If you are running Nexus across namespace or trust boundaries and want to evaluate request-bound authorization against your architecture, [get in touch](https://tenuo.ai/early-access.html).

---

*Tenuo is an open-source warrant-based authorization system and part of Temporal's [AI Partner Ecosystem](https://temporal.io/partners/ai). Its delegation model is also described in an individual [Internet-Draft submitted to the IETF OAuth Working Group](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/).*
