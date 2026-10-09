# Architectural patterns

Use this reference to choose where verification and effect execution belong. The same warrant semantics can be used in several topologies; their security properties differ because bypass resistance and trust ownership differ.

## Selection criteria

For each candidate, answer:

- Does it see the final capability name and every material effective argument?
- Does it run before the effect and return verified arguments to the executor?
- Can the agent or compromised workload bypass, reconfigure, or stop it?
- Where do trusted roots, holder keys, revocation state, nonces, and approvals live?
- What happens on timeout, restart, partition, overload, or policy-update failure?
- Can a denial be proven to leave the effect untouched?

Prefer the simplest pattern that establishes the required boundary. More processes do not automatically mean stronger enforcement.

## Embedded in the agent process

The SDK wraps local tools or framework callbacks in the same process that chooses actions.

Use it for accidental model behavior, rapid adoption, local tools, and applications where the process itself is trusted. It offers low latency and direct access to typed arguments.

It is not an independent boundary against arbitrary code execution in that process. Remove direct credentials and alternate clients where possible, and describe it as an in-process guardrail when bypass remains possible.

## Embedded at the effecting service

The API handler, MCP server, database broker, worker, or other resource-owning service verifies immediately before its own operation.

This is usually the clearest independent boundary because it sees domain arguments and controls the effect. Ensure every handler and administrative route is covered, keep issuer secrets out of the service, and use the verified representation for execution.

## Gateway or API proxy

A gateway verifies calls before forwarding to one or more backend services.

Use it when protocols and authorization-relevant fields are visible at the gateway and backends can reject direct traffic. It centralizes rollout and can protect services that cannot embed an SDK.

Prevent clients from reaching backends directly. Bind the allow decision to the exact forwarded method, destination, identity, and normalized arguments; strip untrusted authorization-result headers. Re-authorize after material gateway rewrites. A gateway that sees only an opaque payload cannot enforce constraints hidden inside it.

## Sidecar

A verifier runs beside each workload and mediates local outbound calls, inbound effects, or both.

Use it for language-neutral local verification, low-latency policy state, and independently managed enforcement. The deployment must force relevant traffic through the sidecar; merely offering a localhost endpoint is not mediation. Protect its socket, configuration, roots, nonce store, and update channel from the agent workload. Decide explicitly whether failure or unavailability denies the effect.

## Service mesh or external authorization hook

The mesh calls an authorization component during request processing.

Use it when the mesh provides a guaranteed pre-upstream hook and enough L7 context. Many mesh hooks see HTTP metadata but not framework tool semantics or decoded application arguments. Map identities and fields deterministically, prevent backend bypass, and bind the decision to the exact request the proxy sends upstream.

## MCP or remote tool host

The client presents authority with a tool call and the MCP server or tool host verifies before invoking the handler.

This maps naturally to capability names and arguments. Verify transport metadata before the handler, account for framework defaults and schema transformations, reject missing authority when enforcement is intended, and ensure retries or approval resubmissions use the selected replay policy.

## Queue and worker

Authority travels with a job, and the worker verifies immediately before an external effect.

Use it for asynchronous work and durable delegation. Protect warrant and proof fields from message rewriting, bind them to the effective job payload, handle delayed jobs against expiry and revocation state, and make redelivery idempotent. Authorization at enqueue time alone is insufficient when the worker executes later under different conditions.

## Workflow engine activity boundary

Workflow orchestration carries authority while each effecting activity verifies before execution.

Use it when workflows replay or resume and activities own the external effects. Keep private keys out of serialized workflow history, define how authority is refreshed or expires during long workflows, and distinguish deterministic workflow replay from real activity re-execution. Apply idempotency at the activity's effect.

## Central decision service with distributed enforcement points

A central component evaluates policy while gateways, sidecars, or services enforce the result.

Use it when centralized policy management is required, but keep the policy decision point distinct from the enforcement point. Authenticate both directions and cryptographically or transactionally bind each decision to the caller, capability, arguments, destination, and freshness window. Do not allow a stale or transferable “allow” response to authorize a different request.

## Hybrid pattern

Larger systems commonly issue and approve authority centrally, distribute roots and revocation state, and verify locally at gateways, sidecars, or effecting services.

Document which component owns issuance, signing, verification, replay state, revocation freshness, receipts, and the effect. A diagram is useful only if it also shows bypass routes and trust boundaries.
