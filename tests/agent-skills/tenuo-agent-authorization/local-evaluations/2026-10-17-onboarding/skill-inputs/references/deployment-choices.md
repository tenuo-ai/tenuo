# Choose ownership and enforcement

Recommend the smallest deployment that covers the user's threat model and actual
effect routes. Make two choices independently: **who issues/manages authority**
and **where the effect is enforced**. Cloud management does not by itself move
verification outside the agent, and a separate process does not force mediation.

## Issuance and management

| Choice | Fits | What the project must establish |
| --- | --- | --- |
| Application-owned issuer and SDK | A bounded task flow with existing trusted business logic and key management | Issuer derives concrete limits from trusted records, binds the holder, distributes roots/SRLs as needed; agent cannot mint replacement authority. |
| Local CLI/templates, when installed | Developer setup and operator-managed local workflows | Verify the actual parser/commands and full hardened source stack. Separate files under one user demonstrate a development loop, not isolation. |
| Tenuo Cloud | Managed identities, issuance templates/triggers, approval delivery, revocation distribution and receipt collection | Resolve the Cloud package/service version too. Verify initiator permissions, event bindings, holder identity, explicit roots, enforcement mode, provider wiring and key ownership. |

With Cloud, distinguish the reusable template, the trigger's issuance policy and
event bindings, and the concrete signed warrant returned for a task. A plan or
retrieved note is not a trusted event source for a payee, budget or resource ID.
Use the actual service schema and installed SDK; local YAML templates and Cloud
template/trigger JSON are different contracts, not interchangeable encodings.
Inspect dry-run/preview output before using a supported issuance path. Do not
create accounts, fire real production triggers or publish configuration merely
to explain a proposal.

The normal split is centrally or application-issued task authority, holder-local
attenuation, and verification at the effect boundary using public trust data.
Offline verification does not require an issuer round-trip at every delegation
or invocation. Issuance, trust/SRL refresh, approvals and receipt delivery may
still require network access. State the actual outage and freshness behavior;
neither unlimited offline operation nor a Cloud call on every effect is implied.

Check integration defaults: a convenience helper may trust its own signing key,
start in observe mode, or enable only a best-effort event stream. Configure the
intended roots and enforce mode explicitly and test them. Use the installed
native receipt sink/provider when signed artifact delivery is required; a
dashboard event is not automatically an offline-verifiable receipt.

## Effect enforcement

| Project shape / threat | Recommended starting point | Verify before claiming coverage |
| --- | --- | --- |
| Trusted application process; model-selected calls are the concern | Embedded local constraints or warrants around actual effects | Final arguments are checked; original routes are covered. This can be production enforcement when trusted code owns the boundary. |
| Agent may run arbitrary code or reach raw provider credentials | Independent effect service, MCP host or effect worker | Move provider credentials and issuer secrets out of the agent; deny raw/direct paths. An agent-side wrapper alone cannot contain that process. |
| Remote MCP tools | Server-side verification before handlers, or a forced proxy path | Real metadata/chain/PoP transport, defaults and canonicalization, SDK-major compatibility, no direct unguarded endpoint. |
| Temporal or asynchronous jobs | Effecting activity/job worker | Public authority transport, root-only verification, expiry on delayed execution, retries and idempotency. Enqueue/start authorization alone is insufficient. |
| Existing gateway, sidecar or mesh | Its guaranteed pre-effect hook, if it sees material arguments | Exact forwarded request binding, backend/network bypass prevention, protected configuration and fail-closed behavior. Do not add infrastructure solely because the framework is unfamiliar. |
| Delegating agents / A2A | Separate holder keys across useful authority boundaries plus receiver verification | Child has only its task grant and key; complete chain reaches trusted-root verification; remaining parent authority is not available to the child. |

For detailed topology tradeoffs, read [Architectural patterns](architectural-patterns.md).
The project proposal should name the chosen issuer, holder and verifier/effect
owner, where their keys/credentials live, the bypass being closed, and the
smallest deployment change needed. Explain one relevant alternative and why it
does or does not fit; do not dump every topology on the developer.

## What the design guarantees

Authority includes the task's resource designation and tool arguments, so a
deputy acts under received task authority rather than ambient service access.
OAuth/workload identity and task authority can coexist. The useful distinction
is holder-derived narrowing and independently verifiable delegation, not an
assertion that OAuth, RBAC or policy engines cannot express argument limits.

Give a worker its own holder key and only the derived task authority. Public
parent warrants must travel with the chain, but parent private keys and broader
usable credentials must not. Derivation does not revoke the parent; a process
that still holds a broader usable grant can choose it instead. Neither role
names nor protocol signatures isolate processes or infer business intent.

Preserve each link's holder/signature, depth, lifetime, capability containment
and parent linkage, then check leaf proof and final arguments. Constraint
containment is structural and version-dependent; arbitrary policy expressions
are not automatically safe to delegate. A valid signature alone is insufficient.

Use the IETF draft as design context, not as a claim of installed conformance.
The -02 working text's JWT/JWS profile, explicit token typing, audience and
stateful proof replay requirements must not be transplanted into Tenuo's
released CBOR/COSE warrant/PoP API. MCP/HTTP bindings are separate contracts.
The base draft leaves approval and revocation profiles to other specifications;
Tenuo has its own implementations to inspect. Do not promise JWT interoperability,
nonce/JTI consumption or shared replay state without a tested implementation.
Likewise, do not claim separate issuer/execution token types are universal draft
requirements: root/leaf are chain positions; check Tenuo's concrete warrant types.

Stateful total budgets, call-count limits, one-use execution and exactly-once
effects need additional application controls. Approval authorizes the exact
eligible in-scope call; it cannot widen the warrant. Receipts attest to decisions
and any verified approval artifacts, not necessarily downstream completion.

## Sources and illustrative deployments

At refresh time, inspect core verifier/adapters and the relevant Cloud source,
then use demos for the deployment story. If private Cloud source is unavailable,
use installed artifacts and matching customer documentation or identify the
specific unknown; private-repository access is not a prerequisite for local SDK
onboarding. Do not copy operational secrets or private source into the project.

- Core design and implementation: [enforcement architecture](https://github.com/tenuo-ai/tenuo/blob/v0.3.2/docs/enforcement.md), [core planes/verifier](https://github.com/tenuo-ai/tenuo/blob/v0.3.2/tenuo-core/src/planes.rs), and the target's exact adapter source/tests. Documentation snippets still need runtime verification.
- Pending design: [IETF -02 working text](https://github.com/tenuo-ai/tenuo/pull/667), branch `aat/ietf-vectors-02`, reviewed at `ba7878bc72c3f5d289a75051029209d30741b306`, especially introduction, invariants and security considerations. This is an unmerged working draft, not a released SDK contract.
- [Invoice processing](https://github.com/tenuo-ai/tenuo-demos/tree/936b3c77c1a2b27b78933713bd2626ede416651d/invoice-processing): task-bound bank account in a LangGraph payment flow; local and Cloud management choices. Full demo needs services and a model key; do not call it a one-command/no-key quickstart.
- [Order repair](https://github.com/tenuo-ai/tenuo-demos/tree/936b3c77c1a2b27b78933713bd2626ede416651d/temporal-order-repair): issuer loads trusted order data; separate repair-tools worker verifies with public keys; signed approvals and optional Cloud management. Multi-process setup is a deployment illustration, not the shortest first demo.
- [OpenAI/MCP delegation](https://github.com/tenuo-ai/tenuo-demos/tree/936b3c77c1a2b27b78933713bd2626ede416651d/openai-mcp-delegation): parent/worker keys, narrower service arguments and independent server verification. Its deterministic cases need no model key. Verify its resolved SDK and current deny-before-effect tests before recommending it.

These pinned demos document examples inspected during skill development, not
current runtime guarantees or a promise that every demo was executed here.
