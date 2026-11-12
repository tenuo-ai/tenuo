<p align="center">
  <img src="docs/images/tenuo-logo.svg" alt="tenuo" width="200">
</p>

<p align="center">
  <strong>Task-scoped authorization for AI agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml"><img src="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/tenuo"><img src="https://img.shields.io/crates/v/tenuo.svg" alt="Crates.io"></a>
  <a href="https://pypi.org/project/tenuo/"><img src="https://img.shields.io/pypi/v/tenuo.svg" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/tenuo/authorizer"><img src="https://img.shields.io/docker/v/tenuo/authorizer?label=docker&sort=semver" alt="Docker"></a>
  <a href="https://tenuo.ai"><img src="https://img.shields.io/badge/docs-tenuo.ai-blue" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://deepwiki.com/tenuo-ai/tenuo"><img src="https://img.shields.io/badge/Ask-DeepWiki-blue.svg" alt="Ask DeepWiki"></a>
</p>

Tenuo lets you define what an agent may do for a task, carry that authority across services and agent handoffs, and enforce it where actions execute. Each handoff can only narrow the authority granted.

That authority travels as a **warrant**: a signed grant specifying allowed tools, argument constraints, and an expiry.

- **Across frameworks and runtimes.** Delegate between agents and services using different languages and frameworks.
- **Across organizations and trust domains.** Grant limited authority to others and independently verify the authority you receive.
- **Online or air-gapped.** Verify locally without contacting a central authorization service, using provisioned trust keys and local revocation state.

Open source. Works alongside your existing identity and policy systems.

## Install

```bash
# Python
pip install tenuo

# TypeScript (beta, Node 20+)
npm install @tenuo/core@beta

# Rust
cargo add tenuo --features sdk
```

To try Tenuo without installing an SDK:

<a href="https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open In Colab"></a>
<a href="https://tenuo.ai/explorer/"><img src="https://img.shields.io/badge/Explorer-decode_warrants-1a1a1a" alt="Explorer"></a>
<a href="https://tenuo.ai/demo.html"><img src="https://img.shields.io/badge/Docker_Demo-delegation_chain-333333" alt="Docker Demo"></a>
<a href="https://niyikiza.com/posts/tenuo-launch/"><img src="https://img.shields.io/badge/Blog-Why_Tenuo%3F-ff6b6b" alt="Blog"></a>

<a id="quick-start-from-one-tool-to-delegated-work"></a>

## Quick Start

Give an agent permission to request up to ten replicas. Calls outside that limit are blocked before the function executes. These examples simulate the action by returning a message.

### Python

Save as `quickstart.py` and run `python quickstart.py`.

```python
from tenuo import Capability, Range, SigningKey, configure, guard, mint_sync
from tenuo.exceptions import AuthorizationDenied

# Local development setup.
configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

@guard(tool="scale")
def scale(replicas: int) -> str:
    return f"Requested {replicas} replicas"

with mint_sync(Capability("scale", replicas=Range.max_value(10)), ttl=60):
    print(scale(3))

    try:
        scale(20)
    except AuthorizationDenied:
        print("Blocked before the function ran")
```

### TypeScript · Beta

Save as `quickstart.mts` and run `npx tsx quickstart.mts`.

```typescript
import { AuthorizationDeniedError, createTenuo, range } from "@tenuo/core";

// Local development setup: this process holds the issuance key.
const tenuo = createTenuo({
  root: createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey()),
});

const scale = tenuo.tool(
  {
    execute: async ({ replicas }: { replicas: number }) =>
      `Requested ${replicas} replicas`,
  },
  { capability: "scale", allow: { replicas: range({ max: 10 }) } },
);

const session = tenuo.session({ tools: [scale], ttlSeconds: 60 });

await tenuo.withSession(session, async () => {
  console.log(await scale.execute({ replicas: 3 }));

  try {
    await scale.execute({ replicas: 20 });
  } catch (error) {
    if (!(error instanceof AuthorizationDeniedError) ||
        error.code !== "TENUO_CONSTRAINT_VIOLATION") throw error;
    console.log("Blocked before the function ran");
  }
});
```

Both examples produce:

```text
Requested 3 replicas
Blocked before the function ran
```

These examples keep issuance and enforcement in one process for development. Python's `dev_mode=True` also relaxes trust-root and audit-log checks. To enforce limits against an untrusted agent, keep issuance keys outside its reach and verify at a tool service or gateway it cannot bypass. The [MCP walkthrough](./docs/mcp.md) shows that setup with a server that holds only the issuer's public key. The [Production Guide](./docs/production-guide.md) covers enforcement modes, rollout, and key management.

Leaving the scoped block ends its local authorization context; it does not revoke a signed warrant. Keep warrant lifetimes short.

**Continue with:** [Python guide](./docs/quickstart.md) · [TypeScript guide](./tenuo-ts/README.md) · [Rust guide](#rust) · [MCP walkthrough](./docs/mcp.md)

The TypeScript guide's examples use `createTenuo.devRoot()`, which requires `NODE_ENV=development`.

## Delegate Across Boundaries

A task can move between agents, frameworks, and services while retaining its authorization limits.

```text
Issuer                  Orchestrator               Worker
Grants authority   →    Narrows for a subtask   →   Presents warrant
                                                    ↓
                                               Receiving service
                                               Verifies before acting
```

For example, a Python orchestrator can delegate a narrower warrant to a TypeScript worker calling a Rust service. The receiving service verifies the chain against its configured trusted roots, then checks the caller's proof of possession and the requested action against the warrant.

A delegated warrant can only narrow its parent:

```python
from tenuo import Range, SigningKey, Warrant
from tenuo.exceptions import MonotonicityError

issuer = SigningKey.generate()
orchestrator = SigningKey.generate()
worker = SigningKey.generate()

root = (Warrant.mint_builder()
    .capability("scale", replicas=Range.max_value(10))
    .holder(orchestrator.public_key)
    .ttl(300)
    .mint(issuer))

# The orchestrator hands the worker a lower limit and a shorter lifetime.
worker_warrant = (root.grant_builder()
    .capability("scale", replicas=Range.max_value(5))
    .holder(worker.public_key)
    .ttl(60)
    .grant(orchestrator))

try:
    (root.grant_builder()
        .capability("scale", replicas=Range.max_value(50))
        .holder(worker.public_key)
        .ttl(60)
        .grant(orchestrator))
except MonotonicityError:
    print("Rejected: a child cannot raise the limit")
```

In TypeScript, use [`tenuo.narrow()`](./tenuo-ts/README.md#delegate-to-another-agent).

Sensitive actions can also require a [signed human approval](./docs/approvals.md).

**Explore:** [Python MCP delegation demo](./tenuo-python/examples/mcp/mcp_delegation_demo.py) · [Security model](./docs/security.md) · [Supported integrations](#integrate-at-the-boundary-you-control)

## Integrate at the Boundary You Control

Tenuo uses the same warrant format and attenuation rules everywhere. Pick the enforcement point that fits. Authority crosses these boundaries without translation.

| Enforcement point | Use it when | Integrations | Start here |
|-------------------|-------------|--------------|------------|
| **Inside the agent runtime** | You own the application and want the shortest path to enforcement | Python functions, OpenAI, LangChain, LangGraph, Google ADK, CrewAI, AutoGen, Hermes Agent, Rust `Guard` | [`@guard`](./docs/quickstart.md), [OpenAI](./docs/openai.md), [Hermes](./docs/hermes.md), [Rust](#rust), [framework guides](#documentation) |
| **At the MCP tool server** | Agents call tools across a process or vendor boundary | FastMCP, official MCP SDK, custom MCP servers | [MCP guide](./docs/mcp.md) |
| **At an API or service edge** | Multiple agent runtimes share the same downstream services | FastAPI, authorizer sidecar, gateway, Kubernetes | [FastAPI](./docs/fastapi.md), [Kubernetes](./docs/kubernetes.md) |
| **Inside a durable workflow** | Authority must survive retries, queues, and long-running execution | Temporal | [Temporal guide](./docs/temporal-reference.md) |
| **At an agent handoff** | One agent delegates part of a task to another agent | A2A, MCP warrant stacks | [A2A guide](./docs/a2a.md), [delegation demo](./tenuo-python/examples/mcp/mcp_delegation_demo.py) |

These are deployment choices for one authorization system. A warrant can be verified anywhere its issuer is trusted, and every delegated warrant must remain within its parent.

---

## Security Boundaries

Tenuo checks the warrant and the actual tool arguments before an action executes. Enforcement must run at a boundary the agent cannot modify or bypass; an in-process guard alone does not isolate an untrusted agent.

Tenuo complements your identity system and policy controls. Use a container or VM when you need process isolation. For disconnected deployments, provision trusted keys and revocation state in advance; offline verification cannot discover revocations it has not received.

See the [security model](./docs/security.md) for guarantees and limitations.

## Deploying to Production

The self-hosted core and sidecar are Apache-2.0 and run entirely in your infrastructure, with no external calls at verification time.

**Self-hosted checklist:**

- Store signing keys in a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager). Keep them out of environment variables
- Configure `trusted_roots` with your control plane's public keys
- Ensure `dry_run` is disabled and warrants are required in all enforcement points
- Enable audit callbacks and metrics for observability

See the [Production Guide](./docs/production-guide.md) for enforcement modes, gradual rollout, and key management, and the [Security Model](https://tenuo.ai/security) for the full threat model.

### Tenuo Cloud (Optional)

[Tenuo Cloud](https://cloud.tenuo.ai/) is an optional managed control plane for issuance, key rotation, hosted revocation distribution, observability, and multi-tenant isolation. Verification stays local. Self-hosted Tenuo already verifies warrants and signed revocation lists (SRLs) in your own infrastructure.

---

## Docker & Kubernetes

**Try the Demo**:

```bash
docker compose up
```

This runs the [orchestrator -> worker -> authorizer](https://tenuo.ai/demo.html) stack: issuance, delegation, and verification.

**Official Images** on [Docker Hub](https://hub.docker.com/u/tenuo):

```bash
docker pull tenuo/authorizer:0.3.7  # Sidecar for warrant verification
docker pull tenuo/control:0.3.7     # Control plane (demo/reference)
```

**Helm Chart**:

```bash
helm install tenuo-authorizer ./charts/tenuo-authorizer \
  --set config.trustedRoots[0]="YOUR_CONTROL_PLANE_PUBLIC_KEY"
```

See [Helm chart README](./charts/tenuo-authorizer) and [Kubernetes guide](https://tenuo.ai/kubernetes).

---

## Documentation

| Resource | Description |
|----------|-------------|
| **[AI Agent Delegation Security Lab](./labs/agent-delegation/README.md)** | A hands-on lab: six agents, one rogue, five core levels plus two optional bosses |
| **[Quickstart](https://tenuo.ai/quickstart)** | Get running in 5 minutes |
| **[Concepts](https://tenuo.ai/concepts)** | How warrants and attenuation work |
| **[Constraints](https://tenuo.ai/constraints)** | All 11 constraint types explained |
| **[Security](https://tenuo.ai/security)** | Threat model and guarantees |
| **[OpenAI](https://tenuo.ai/openai)** | Direct API protection with streaming |
| **[Google ADK](https://tenuo.ai/google-adk)** | ADK agent tool protection |
| **[AutoGen](https://tenuo.ai/autogen)** | AgentChat tool protection |
| **[Hermes Agent](https://tenuo.ai/hermes)** | Official Hermes plugin for signed, expiring tool authorization |
| **[A2A](https://tenuo.ai/a2a)** | Inter-agent delegation |
| **[FastAPI](https://tenuo.ai/fastapi)** | Protect FastAPI routes |
| **[LangChain](https://tenuo.ai/langchain)** | Tool protection |
| **[LangGraph](https://tenuo.ai/langgraph)** | Multi-agent graph security |
| **[CrewAI](https://tenuo.ai/crewai)** | Multi-agent crew protection |
| **[Temporal](https://tenuo.ai/temporal)** | Durable workflow authorization |
| **[MCP](https://tenuo.ai/mcp)** | Model Context Protocol client + server verification |

### AI Coding Agents

Install Tenuo's implementation skill so a supported coding agent can place
authorization at the effect boundary, use the SDK version in your project, and
generate both allow and deny-before-effect tests:

```bash
npx skills add tenuo-ai/tenuo --skill tenuo-agent-authorization
```

The skill distinguishes an in-process guardrail from an independently enforced
boundary and reports the guarantee and remaining bypasses explicitly. It does
not ask the agent to reimplement Tenuo's cryptography or protocol.

## Try It: The AI Agent Delegation Security Lab

A travel assistant made of six AI agents is booking a spring-break trip. One of them has been told to do something it shouldn't. Secure the system so the trip still happens and the rogue agent gets nowhere.

```bash
git clone https://github.com/tenuo-ai/tenuo
cd tenuo/labs/agent-delegation
npm install
npm run lab
```

Five main levels plus two optional bosses, no agent-framework experience needed. Book the trip, stop the rogue agent, and learn why each handoff should carry only the authority its task needs. Runs offline with free retries and no API key. The guide is at [tenuo.ai/lab](https://tenuo.ai/lab/); the code is in [`labs/agent-delegation`](./labs/agent-delegation/README.md).

---

## Requirements

| Component | Supported |
|-----------|-----------|
| **Python** | 3.9 - 3.14 |
| **Node.js** | **Beta**. Node 20+ (`npm i @tenuo/core@beta`) |
| **OS** | Linux, macOS, Windows |
| **Python installation** | Prebuilt wheels for Linux (x86_64 and aarch64), macOS (arm64), and Windows (x64). Other platforms build from source and need Rust |

### Optional Dependencies

With uv, use `uv pip install` in place of `pip install`.

```bash
pip install tenuo                     # Core only
pip install "tenuo[openai]"           # + OpenAI Agents SDK
pip install "tenuo[google_adk]"       # + Google ADK
pip install "tenuo[a2a]"              # + A2A (inter-agent delegation)
pip install "tenuo[fastapi]"          # + FastAPI integration
pip install "tenuo[langchain]"        # + LangChain (langchain-core ≥0.2)
pip install "tenuo[langgraph]"        # + LangGraph (includes LangChain)
pip install "tenuo[crewai]"           # + CrewAI
pip install "tenuo[temporal]"         # + Temporal workflows
pip install "tenuo[autogen]"          # + AutoGen AgentChat (Python ≥3.10)
pip install "tenuo[mcp]"              # + official MCP SDK, client & server verification (Python ≥3.10)
pip install "tenuo[fastmcp]"          # + FastMCP (TenuoMiddleware / FastMCP servers)
pip install "tenuo[cloud]"            # + Tenuo Cloud SDK (proprietary control-plane client)
```

---

## Rust

The core crate is the protocol. The `sdk` feature is the enforcement surface: a guard that checks a call before it runs, an authority that binds a warrant chain to a signing key, cryptographic delegation, an observe mode, and MCP and HTTP transports.

```toml
[dependencies]
tenuo = { version = "0.3.7", features = ["sdk"] }
```

```rust
use std::time::Duration;
use tenuo::sdk::prelude::*;
use tenuo::{args, constraints};

let root = SigningKey::generate(); // in production this lives in your control plane
let holder = SigningKey::generate();

let warrant = Warrant::builder()
    .capability("read_file", constraints! { "path" => Pattern::new("/data/*")? })
    .holder(holder.public_key())
    .ttl(Duration::from_secs(300))
    .build(&root)?;

let runtime = Runtime::builder()
    .holder(holder)
    .trusted_root(root.public_key())
    .revocation(RevocationMode::TtlOnly { max_lifetime: Duration::from_secs(600) })
    .build()?;
let session = runtime.session_from_warrant(warrant)?;

let allowed = Call::owned("read_file", args! { "path" => "/data/report.csv" })?;
let out = session.guard(&allowed, |_| Ok::<_, std::io::Error>("read"))?;
assert_eq!(out.into_inner(), "read");

let refused = Call::owned("read_file", args! { "path" => "/etc/shadow" })?;
assert!(session.check(&refused).is_err());
```

The closure runs only after an allow. A call outside the constraint is denied before it runs, same as Python `@guard`. A guard with no trust root or no revocation policy does not compile.

Features, all off by default: `sdk`, `mcp-transport`, `http-transport`, `async`, `receipts`, `otel`, `test-utils`. The default build adds no extra crates.

Use Rust for authorizer sidecars, gateways, MCP servers built on `rmcp`, and any service that needs enforcement without a Python runtime.

- API docs: [docs.rs/tenuo](https://docs.rs/tenuo)
- Security model: [tenuo.ai/security](https://tenuo.ai/security)
- Constraints reference: [tenuo.ai/constraints](https://tenuo.ai/constraints)

---

## How It Works

Tenuo is capability-based authorization. A warrant is a capability: a signed grant that lists the tools an agent may call, the argument values it may pass, the key that may use it, and when it expires. The warrant travels with the request. The verifier uses the trusted issuer key and locally available revocation state.

**Holder-bound.** Every warrant names a public key. Every call carries a signature from that key over the warrant, the tool, the exact arguments, and a short time window. A copied warrant is useless without the key.

**Verified offline.** The warrant carries its own authority and signature. Checking it needs no lookup and no network. Checks run in under 50 μs, and enforcement keeps working when the control plane is down.

**Attenuates monotonically.** Delegation mints a child warrant signed by the parent's holder. The verifier walks the whole chain from a trusted root to the leaf. Each link may drop tools, tighten constraints, or shorten expiry. No delegated warrant can exceed its parent. Tenuo calls this **Subtractive Delegation**.

**Holds under prompt injection.** The check never asks the model. It runs at the tool boundary, on the real arguments, after the model has chosen what to call. A hijacked agent can only make the calls its warrant already allowed.

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Control Plane   │     │  Orchestrator    │     │  Worker          │
│                  │     │                  │     │                  │
│  Issues root     │────▶│  Attenuates      │────▶│  Executes with   │
│  warrant         │     │  for task        │     │  proof           │
└──────────────────┘     └──────────────────┘     └──────────────────┘
     Full scope     -->     Narrower      -->      Narrowest
```

1. **Control plane** issues a root warrant with broad capabilities
2. **Orchestrator** attenuates it for a specific task; scope can only shrink
3. **Worker** proves possession of the bound key and executes

See [Concepts](https://tenuo.ai/concepts) for the model and [Related Work](./docs/related-work.md) for how this compares to Biscuit, Macaroons, UCAN, and [CaMeL](https://arxiv.org/abs/2503.18813).

---

## Why Tenuo?

IAM answers who you are. Tenuo answers what this workload may do for this task, right now. Agents stay free to plan and pick tools. The warrant still applies after they choose.

| Existing limitation | Tenuo |
|---------------------|-------|
| IAM typically grants authority by identity or role | Warrants limit authority to the current task |
| Conventional agent handoffs do not carry the original authorization context | Authority travels with the work and can only narrow |
| Plain bearer tokens can be copied or replayed | Every warrant is bound to the key using it |
| Central policy checks introduce a runtime dependency | Signed authority is verified locally at execution |
| Generic string matching can disagree with downstream systems | [Semantic constraints](https://tenuo.ai/constraints) interpret arguments as the target does ([why this matters](https://niyikiza.com/posts/cve-2025-66032/)) |

Signed authorization receipts are opt-in when you need to show why a call was allowed or denied.

---

## Prior Art

Tenuo builds on capability token ideas described in [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). Inspired by [Macaroons](https://research.google/pubs/pub41892/), [Biscuit](https://www.biscuitsec.org/), and [UCAN](https://ucan.xyz/).

The token format and delegation protocol are specified in [Attenuating Authorization Tokens for Agentic Delegation Chains](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/), an active individual Internet-Draft in the IETF OAuth Working Group. The core attenuation rules are formally verified with [Alloy](docs/formal_verification/aat_constraints.als) (capability and argument-key monotonicity) and [Z3](docs/formal_verification/z3_bounds.py) (constraint-type subsumption bounds).

See [Related Work](https://tenuo.ai/related-work) for detailed comparison.

---

## Featured In

- [TLDR InfoSec](https://tldr.tech/infosec/2026-01-13) - "The Map is not the Territory: The Agent-Tool Trust Boundary"
- [TLDR InfoSec](https://tldr.tech/infosec/2025-12-15) - "Capabilities Are the Only Way to Secure Agent Delegation"
- [Awesome Object Capabilities](https://github.com/dckc/awesome-ocap) - Curated list of capability-based security resources
- [Awesome LangChain](https://github.com/kyrolabs/awesome-langchain)
- [Awesome LLM Agent Security](https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security)
- [Awesome LLMSecOps](https://github.com/wearetyomsmnv/Awesome-LLMSecOps)

---

## Etymology

**Tenuo** (/tɛn-ju-oʊ/ • *Ten-YOO-oh*)

From Latin *tenuare*: "to make thin; to attenuate."
Authority starts broad at the root and is **attenuated** as it flows down the delegation chain.

---

## Contributing

Tenuo is Apache-2.0 and built in the open. The core is Rust, with Python and TypeScript SDKs on top. Good places to start:

- **Framework integrations.** Adapters live in `tenuo-python/tenuo/`. The [integration guide](tenuo-python/docs/integration-guide.md) covers the required API patterns and invariant tests. [OpenAI](tenuo-python/tenuo/openai.py) and [Google ADK](tenuo-python/tenuo/google_adk/guard.py) are good templates.
- **Constraint types.** There are 11 today. A new one has to parse input the same way the target system does.
- **The Rust SDK.** New in 0.2.4. Adapters for Rust agent frameworks are open ground.
- **The TypeScript SDK.** It is in beta and needs real-world use.
- **Docs and examples.** If a guide confused you, that is a bug worth filing.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, and the PR process.

**Security issues**: Email security@tenuo.ai with PGP ([key](./SECURITY_PUBKEY.asc)). Please do not open public issues for these.

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
