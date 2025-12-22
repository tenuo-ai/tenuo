# SecureGraph Specification

> ⚠️ **Status: Conceptual Exploration — Not Planned**
> 
> This document explores a declarative attenuation layer for LangGraph. The core concepts (warrant flow through state, automatic attenuation at transitions) are valid, but the current Tenuo API (`@tenuo_node`, `scoped_task`, `protect_tools`) already covers most use cases with less complexity. Preserved for reference.

**Version**: 0.2  
**Status**: Conceptual (not planned)

---

## Table of Contents

1. [Philosophy](#philosophy)
2. [Mental Model](#mental-model)
3. [Core Invariant](#core-invariant)
4. [Cryptographic Integrity](#cryptographic-integrity)
5. [Cycle Protection](#cycle-protection)
6. [State Schema](#state-schema)
7. [Warrant Flow](#warrant-flow)
8. [API](#api)
9. [Attenuation Modes](#attenuation-modes)
10. [Error Messages](#error-messages)
11. [Implementation](#implementation)
12. [Conditional Edges](#conditional-edges)
13. [Cycles](#cycles)
14. [Export for Audit](#export-for-audit)
15. [v0.3 Features](#v03-features-deferred)
16. [Summary](#summary)

---

## Philosophy

SecureGraph is **declarative attenuation**, not access control.

Traditional systems (RBAC, ACL) answer: "Who is allowed to do what?"  
Capability systems answer: "What authority does this request carry?"

SecureGraph enforces a single invariant:

> **No Amplification Rule**: A node can NEVER receive authority that the incoming warrant does not possess.

Policy defines the **ceiling**. Incoming warrant defines the **actual**. Node receives the **intersection**.

### No Amplification Law

For any execution step *n*:

```
Authority(n+1) ⊆ Authority(n)
```

This is the fundamental security guarantee. Authority can only shrink, never expand.

---

## Mental Model

### What SecureGraph Is

```
SecureGraph = Declarative Attenuation
```

Instead of writing this in every node:

```python
async def researcher(state):
    parent = get_warrant()
    child = parent.attenuate().capability("search", {"path": Pattern("/data/*")}).delegate(keypair)
    with warrant_context(child):
        return await do_research(state)
```

You declare it once:

```python
secure.node("researcher", capabilities=[Capability("search", path=Pattern("/data/*"))])
```

SecureGraph performs the `attenuate()` call on your behalf at each transition.

### What SecureGraph Is NOT

- **Not an authorization server** - it doesn't grant authority
- **Not RBAC** - nodes don't have "roles" that confer permissions  
- **Not a policy engine** - it doesn't evaluate rules against identity

SecureGraph is a **proxy that automates warrant attenuation**.

---

## Core Invariant

```python
def attenuate_for_node(incoming: Warrant, policy: NodePolicy) -> Warrant:
    """
    Policy defines CEILING.
    Incoming warrant defines ACTUAL.
    Node receives INTERSECTION.
    """
    policy_tools = set(policy.tools) if policy.tools else set()
    actual_tools = set(incoming.tools) if incoming.tools else set()
    
    granted_tools = policy_tools & actual_tools  # Intersection
    
    if not granted_tools and policy_tools:
        # Policy wants tools that warrant doesn't have
        raise AttenuationError(
            f"No authority overlap. Policy wants {policy_tools}, "
            f"warrant has {actual_tools}"
        )
    
    return incoming.attenuate() \
        .capability(granted_tools[0] if granted_tools else None, policy.constraints) \
        .delegate(keypair)
```

**Test case for philosophical consistency:**

| Policy says | Warrant has | Node receives | Correct? |
|-------------|-------------|---------------|----------|
| `["search"]` | `["search", "read"]` | `["search"]` | [OK] Attenuated |
| `["search", "read"]` | `["search"]` | `["search"]` | [OK] Intersection |
| `["read"]` | `["search"]` | ERROR | [OK] No overlap |
| `["read"]` | `["search", "read"]` | `["read"]` | [OK] Attenuated |

If your implementation ever grants `["read"]` when the warrant only has `["search"]`, you've built RBAC, not capabilities.

---

## Cryptographic Integrity

SecureGraph enforces cryptographic verification at every node transition. Tampering is detected immediately, not at tool execution.

### Threat Model

| Threat | Attack Vector | Defense |
|--------|---------------|---------|
| Warrant tampering | Malicious node modifies `tenuo_warrant` in state | Signature verification |
| Untrusted issuer | Forged warrant from unknown key | Chain verification to trusted roots |
| Privilege amplification | Node tries to grant more than it has | Attenuation validation |
| Warrant theft (replay) | Stolen warrant reused elsewhere | Proof-of-Possession (PoP) binding |
| Node impersonation | Attacker pretends to be authorized node | PoP with nonce |

### Signature Chain Verification

Every warrant is signed. At deserialization:

SecureGraph follows the canonical wire format (`docs/wire-format-spec.md`): verify against the exact payload bytes *before* deserializing to avoid canonicalization bugs.

```python
def deserialize(raw: bytes, trusted_roots: List[PublicKey]) -> WarrantPayload:
    # 0. Decode outer envelope (SignedWarrant)
    signed = decode(raw)
    if signed.envelope_version != 1:
        raise UnsupportedEnvelopeVersion()
    
    # 1. Extract issuer with minimal parsing (no full deserialize)
    issuer = extract_issuer(signed.payload)
    
    # 2. Verify signature over domain-separated preimage
    preimage = build_preimage(
        signed.envelope_version,
        signed.payload,  # raw CBOR bytes, no re-serialization
    )
    issuer.verify(preimage, signed.signature)  # context: b"tenuo-warrant-v1"
    
    # 3. Now safe to deserialize inner payload
    payload: WarrantPayload = cbor_deserialize(signed.payload)
    if payload.version != 1:
        raise UnsupportedPayloadVersion()
    
    # 4. Validate payload semantics
    #    - trust chain to known roots
    #    - expires_at > now
    #    - max_depth strictly decreases vs parent
    #    - constraints/tool attenuation holds
    validate_payload(payload, trusted_roots)
    return payload
```

**Why this order?**
- Signature validation uses the exact bytes that were signed (no canonicalization gaps).
- Unknown envelope/payload versions or unknown payload keys fail closed (see `docs/wire-format-spec.md` §1–§4, §10).
- Constraint types fail closed per `docs/constraints.md` and the wire format's unknown-type handling.
A malicious node's forged warrant fails before any unsafe parsing or policy evaluation.

### SecureGraph SigningKey Trust

SecureGraph needs a keypair to sign attenuated warrants. The root warrant must authorize it:

```python
# Root authorizes SecureGraph's pubkey as an attenuator
root_warrant = create_root_warrant(
    tools=["search", "read_file", "write_file"],
    path="/*",
    authorized_attenuators=[securegraph_pubkey],
).build(root_keypair)

# SecureGraph uses matching keypair
secure = SecureGraph(
    graph,
    keypair=securegraph_keypair,  # Must match authorized_attenuators
    trusted_roots=[root_pubkey],
)
```

This ensures:
- SecureGraph can attenuate (narrow) the root warrant
- SecureGraph cannot amplify beyond root
- Forged warrants don't chain to root

### Proof-of-Possession (PoP)

Signature chain proves the warrant is valid. PoP proves the caller is authorized to use it.

**Where PoP happens**: At the tool execution boundary, not at node transitions.

```
┌─────────────────────────────────────────┐
│              LangGraph                  │
│                                         │
│  supervisor ──► researcher ──► writer   │
│       │              │            │     │
│       │   (warrants flow, no PoP) │     │
│       ▼              ▼            ▼     │
├───────┴──────────────┴────────────┴─────┤
│            Tool Execution Layer         │
│                                         │
│   protect_tools() enforces PoP here     │
│                                         │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐ │
│   │ search  │  │read_file│  │write_db │ │
│   └─────────┘  └─────────┘  └─────────┘ │
└─────────────────────────────────────────┘
```

Within the graph, nodes are a single trust domain. PoP is enforced at the boundary where tools actually execute.

```python
# In protect_tools
def _protect_tool(tool: Tool, warrant: Warrant):
    async def protected(*args, **kwargs):
        # 1. Check warrant allows this tool
        if tool.name not in warrant.tools:
            raise Unauthorized()
        
        # 2. Check constraints
        if not constraints_satisfied(warrant.constraints, kwargs):
            raise ConstraintViolation()
        
        # 3. PoP check (if warrant is bound)
        if warrant.bound_to:
            nonce = get_current_nonce()
            pop_sig = get_pop_signature()
            if not verify(nonce, pop_sig, warrant.bound_to):
                raise PopVerificationFailed()
        
        return await tool(*args, **kwargs)
    
    return protected
```

### PoP Binding Options

**Graph-level binding** (projected for v0.2):

All warrants bound to a single agent keypair:

```python
root_warrant = create_root_warrant(
    tools=["search", "read_file"],
    bound_to=agent_pubkey,
).build(root_keypair)

# At tool execution
with warrant_context(warrant, pop_keypair=agent_keypair):
    result = await search("query")  # PoP verified
```

**Per-node binding** (v1.0):

Different nodes have different keypairs. SecureGraph re-binds warrants to target node's key at each transition.

---

## Cycle Protection

Cyclic delegation can exhaust memory, CPU, or create infinite loops. SecureGraph uses multiple defense layers.

### Layer 1: Delegation Budget (`max_depth`, cryptographic)

Warrants carry a remaining delegation budget `max_depth` (wire-format §2). Each attenuation MUST strictly decrease it; `max_depth = 0` is terminal.

```python
def attenuate(self, **constraints) -> WarrantBuilder:
    if self.max_depth == 0:
        raise AttenuationError(
            "max_depth=0 (terminal). Cannot attenuate further."
        )
    
    return WarrantBuilder(
        parent=self,
        max_depth=self.max_depth - 1,  # MUST decrease by ≥1
        **constraints,
    )
```

Root warrant sets the ceiling:

```python
root = create_root_warrant(
    tools=["search", "read_file"],
    max_depth=5,
).build(root_keypair)
```

**Cryptographically enforced**: `max_depth` is signed into the payload. Attenuators cannot increase it; verification rejects a child whose `max_depth` is not lower than its parent.

### Layer 2: Warrant Expiry (Cryptographic)

Warrants have a TTL:

```python
root = create_root_warrant(
    tools=["search", "read_file"],
    expires_at=datetime.now() + timedelta(hours=1),
).build(root_keypair)
```

Even if a cycle runs, expired warrants become unusable.

### Layer 3: Terminal = `max_depth == 0` (Cryptographic)

Leaf nodes cannot delegate further once `max_depth` reaches `0`; there is no separate terminal flag in the wire format. SecureGraph's `terminal=True` helper sets the emitted child warrant to `max_depth=0`.

### Layer 4: Graph-Level Visit Limit (Runtime)

SecureGraph tracks node visits per invocation:

```python
class SecureGraph:
    def __init__(
        self,
        # ... existing params ...
        max_node_visits: int = 10,
    ):
        self._max_node_visits = max_node_visits


def _wrap_node(self, node_name: str, fn: Callable, policy: Optional[NodePolicy]):
    async def wrapped(state: Dict[str, Any]) -> Dict[str, Any]:
        # Track visits
        visits = state.get("__tenuo_visits__", {})
        node_visits = visits.get(node_name, 0)
        
        if node_visits >= self._max_node_visits:
            raise CycleDetected(
                f"Node '{node_name}' visited {node_visits} times. "
                f"Max is {self._max_node_visits}. Possible infinite loop."
            )
        
        visits[node_name] = node_visits + 1
        state["__tenuo_visits__"] = visits
        
        # ... rest of wrapper ...
```

### Issuer Warrant Budget

Issuer warrants held by supervisors inherit the same `max_depth` budget. Minted execution warrants must decrement it:

```python
def mint_execution(self, **constraints) -> WarrantBuilder:
    if self.type != WarrantType.ISSUER:
        raise TypeError("Only ISSUER warrants can mint")
    if self.max_depth == 0:
        raise AttenuationError("Issuer max_depth=0; cannot mint further")
    
    return WarrantBuilder(
        type=WarrantType.EXECUTION,
        parent=self,
        max_depth=self.max_depth - 1,  # MUST decrease
        **constraints,
    )
```

For long-running supervisors, seed issuer warrants with a larger `max_depth` budget.

### Defense Summary

| Defense | Where | What it stops |
|---------|-------|---------------|
| `max_depth` | Warrant (crypto) | Unbounded chain length |
| `expires_at` | Warrant (crypto) | Stale warrants in long loops |
| `max_depth=0` (terminal) | Warrant (crypto) | Delegation from leaf nodes |
| `max_node_visits` | SecureGraph (runtime) | Runaway graph execution |

---

## State Schema

### SecuredState Mixin

Users must include warrant fields in their state. We provide a mixin to standardize this:

```python
from tenuo.langgraph import SecuredState

class AgentState(SecuredState):
    input: str
    results: list
    # tenuo_warrant and tenuo_issuer are auto-included
```

Implementation:

```python
class SecuredState(TypedDict, total=False):
    """Mixin that adds Tenuo warrant fields to your state."""
    tenuo_warrant: str   # Execution warrant — flows and attenuates
    tenuo_issuer: str    # Issuer warrant — held by supervisors, never attenuates
```

**Why `tenuo_warrant` not `warrant`?**

`warrant` is a common English word. A legal agent might have a business object called "warrant". Namespacing avoids collision while keeping the key readable.

**Why a mixin?**

- Type checkers know about the field
- Impossible to typo the key name
- Single source of truth for the schema

---

## Warrant Flow

Warrants travel with the request, not in ambient context.

### Basic Flow

```
invoke(state + root_warrant)
  │
  ├─► supervisor
  │     │ state.tenuo_warrant = root_warrant
  │     │
  │     └─► SecureGraph intercepts transition
  │           │ parent = deserialize(state.tenuo_warrant)
  │           │ child = parent.attenuate(researcher_policy)
  │           │ state.tenuo_warrant = serialize(child)
  │           │
  │           └─► researcher
  │                 │ state.tenuo_warrant = attenuated_warrant
  │                 │
  │                 └─► continues...
```

### Supervisor Flow (with Issuer)

The "Supervisor Reset" problem: If `supervisor → researcher → supervisor`, the second supervisor invocation has researcher's attenuated warrant. It loses authority to spawn different workers.

Solution: Supervisors hold an **issuer warrant** that never attenuates.

```
invoke(state + root_warrant + root_issuer)
  │
  ├─► supervisor
  │     │ sees: tenuo_warrant (root), tenuo_issuer (root)
  │     │ mints fresh execution warrant from issuer
  │     │
  │     └─► researcher
  │           │ sees: tenuo_warrant (attenuated), tenuo_issuer = None
  │           │ cannot mint — no issuer access
  │           │
  │           └─► returns to supervisor
  │                 │
  │                 ├─► supervisor
  │                 │     │ sees: tenuo_warrant (narrow), tenuo_issuer (root) ← preserved
  │                 │     │ "Research failed, try Strategy B"
  │                 │     │ mints NEW execution warrant from issuer
  │                 │     │
  │                 │     └─► strategist (fresh scope)
```

**Key insight**: `tenuo_issuer` is **held**, not **passed**.

- Execution warrants flow through edges, attenuating
- Issuer warrants stay with supervisory nodes
- Workers never see `tenuo_issuer` — SecureGraph strips it

### Why State, Not Context?

| Concern | Context-based | State-based |
|---------|---------------|-------------|
| Serialization | Breaks | Works |
| Checkpointing | Breaks | Works |
| Distributed agents | Breaks | Works |
| Audit trail | Implicit | Explicit |
| Philosophy | Ambient authority | Request-carried |

Context vars remain as a **convenience layer** for tool protection. Authority flows through state.

---

## API

### Basic Usage

```python
from tenuo.langgraph import SecureGraph, SecuredState, AttenuationMode

# 1. Define state with mixin
class AgentState(SecuredState):
    input: str
    results: list

# 2. Build graph as usual
graph = StateGraph(AgentState)
graph.add_node("supervisor", supervisor_fn)
graph.add_node("researcher", researcher_fn)
graph.add_node("writer", writer_fn)
graph.add_edge("supervisor", "researcher")
graph.add_edge("researcher", "writer")

# 3. Define attenuation policy
secure = SecureGraph(
    graph,
    keypair=securegraph_keypair,
    trusted_roots=[root_pubkey],           # Required for verification
    mode=AttenuationMode.STRICT,
    verify_on_deserialize=True,            # Default: True
    max_node_visits=10,                    # Runtime cycle protection
)

secure.node("supervisor", holds_issuer=True)
secure.node("researcher", capabilities=[
    Capability("search", path=Pattern("/data/*")), 
    Capability("read_file", path=Pattern("/data/*"))
])
secure.node("writer", capabilities=[Capability("write_file", path=Pattern("/output/*"))], terminal=True)
secure.deny_unlisted()

# 4. Compile
app = secure.compile()

# 5. Invoke with explicit warrants
root_exec = create_execution_warrant(
    capabilities=[
        Capability("search", path=Pattern("/*")),
        Capability("read_file", path=Pattern("/*")),
        Capability("write_file", path=Pattern("/*")),
    ],
    max_depth=10,
    expires_at=datetime.now() + timedelta(hours=1),
    authorized_attenuators=[securegraph_pubkey],
).build(root_keypair)

root_issuer = create_issuer_warrant(
    tools=["search", "read_file", "write_file"],
    path="/*",
    max_depth=100,  # Higher for supervisor minting
    expires_at=datetime.now() + timedelta(hours=1),
).build(root_keypair)

result = await app.ainvoke({
    "input": "Research Q3",
    "tenuo_warrant": root_exec.serialize(),
    "tenuo_issuer": root_issuer.serialize(),
})
```

### Wire-Format Warrant Schema (canonical)

SecureGraph assumes warrants are encoded exactly as in `docs/wire-format-spec.md`. The outer envelope separates signature from payload:

```python
@dataclass
class SignedWarrant:
    envelope_version: int  # currently 1
    payload: bytes         # raw CBOR-encoded WarrantPayload
    signature: Signature   # algorithm-tagged; preimage = b"tenuo-warrant-v1" || envelope_version || payload
```

`payload` encodes the inner warrant:

```python
@dataclass
class WarrantPayload:
    # Versioning
    version: int  # currently 1
    
    # Identity + types
    id: WarrantId
    warrant_type: WarrantType  # EXECUTION | ISSUER (and future types)
    
    # Authority
    tools: Dict[str, ConstraintSet]          # per-tool constraints; see docs/constraints.md
    holder: PublicKey
    issuer: PublicKey
    
    # Time
    issued_at: int     # unix seconds
    expires_at: int    # unix seconds
    
    # Delegation budget
    max_depth: int                     # remaining hops; 0 = terminal
    parent: Optional[WarrantId]        # hash-bound to parent payload bytes
    
    # Metadata
    extensions: Dict[str, bytes] = field(default_factory=dict)
    
    # Auth-critical optional fields (preserved + validated, not ignored)
    issuable_tools: Optional[List[str]] = None
    max_issue_depth: Optional[int] = None
    constraint_bounds: Optional[ConstraintSet] = None
    required_approvers: Optional[List[PublicKey]] = None
    min_approvals: Optional[int] = None
    clearance: Optional[Clearance] = None
```

Key points:
- `max_depth` must strictly decrease on attenuation (child `max_depth` ≤ parent `max_depth - 1`); `max_depth = 0` is the terminal form.
- Unknown payload keys MUST be rejected unless they are inside `extensions` (wire-format §10).
- Unknown constraint types deserialize into `Constraint::Unknown` and fail closed.
- Proof-of-possession bindings should travel in `extensions` (e.g., `tenuo.agent_id`, `tenuo.session_id`) instead of bespoke fields.

### Supervisor Pattern

```python
async def supervisor(state: AgentState) -> AgentState:
    issuer = Warrant.deserialize(state["tenuo_issuer"])
    
    if should_research():
        # Mint execution warrant for researcher
        worker_warrant = issuer.mint_execution(
            Capability("search", path=Pattern("/data/*"))
        ).build(keypair)
    else:
        # Mint different execution warrant for strategist
        worker_warrant = issuer.mint_execution(
            tools=["network"],
            path="/api/*",
        ).build(keypair)
    
    return {
        **state,
        "tenuo_warrant": worker_warrant.serialize(),
        # tenuo_issuer preserved automatically by SecureGraph
    }
```

---

## Node Types

SecureGraph recognizes three node patterns based on policy configuration:

| Node Type | Configuration | Behavior |
|-----------|---------------|----------|
| **Passthrough Node** | `secure.node("name")` (no args) | Inherits parent warrant unchanged. NOT "full authority" - bounded by incoming warrant. |
| **Attenuating Node** | `secure.node("name", tools=[...], ...)` | Narrows authority to intersection of policy and incoming warrant. |
| **Supervisor Node** | `secure.node("name", holds_issuer=True)` | Retains `tenuo_issuer` to mint fresh execution warrants. |

### Passthrough Node

```python
secure.node("router")  # No tools, no constraints
```

A passthrough node does **not** mean "full authority". It means "no additional narrowing at this node". The node receives exactly what the incoming warrant carries — which is already bounded by previous attenuations.

Use passthrough for:
- Routing/orchestration nodes that don't invoke tools
- Nodes where tool selection is dynamic (handled in code)

### Attenuating Node

```python
secure.node("researcher", capabilities=[
    Capability("search", path=Pattern("/data/*")),
    Capability("read_file", path=Pattern("/data/*"))
])
```

Authority is narrowed to the **intersection** of:
- Policy ceiling (tools, constraints defined here)
- Incoming warrant (what the parent actually granted)

### Supervisor Node

```python
secure.node("supervisor", holds_issuer=True)
```

Supervisor nodes hold an issuer warrant (`tenuo_issuer`) that enables them to mint fresh execution warrants for different workers. The issuer warrant is **held**, not **passed** - workers never see it.

---

## Attenuation Modes

```python
class AttenuationMode(Enum):
    STRICT = "strict"           # Fail on violation
    INTERSECT = "intersect"     # Silent narrowing
    REPORT_ONLY = "report_only" # Log and continue
```

### STRICT (default)

Fail if policy requests tools not in warrant.

```python
# Policy: tools=["read_file"]
# Warrant: tools=["search"]
# Result: AttenuationError - no overlap
```

Use STRICT in development and production after policies are tuned.

### INTERSECT

Silently use intersection.

```python
# Policy: tools=["read_file", "search"]
# Warrant: tools=["search"]
# Result: tools=["search"] - silent narrowing
```

Use INTERSECT when you intentionally define broad policies and let warrants constrain.

### REPORT_ONLY

Log violations, don't block. Essential for production rollout.

```python
# Policy: tools=["read_file"]
# Warrant: tools=["search"]
# Result: Logs warning, continues with empty grant
```

```
[TENUO VIOLATION] Node 'researcher' policy violation
  Policy requested: ['read_file']
  Warrant provides:  ['search']
  Missing authority: ['read_file']
  Action: Continuing with [] (REPORT_ONLY mode)
  In STRICT mode, this would raise AttenuationError.
```

Use REPORT_ONLY when adopting Tenuo in an existing app. Deploy to production, watch logs, tune policies, then switch to STRICT.

---

## Error Messages

Violations include actionable diffs:

```python
@dataclass
class AttenuationViolation:
    node: str
    policy_wants: List[str]
    warrant_has: List[str]
    missing: List[str]
    
    def __str__(self) -> str:
        return f"""
╭─ SecureGraph Policy Violation ─────────────────────────╮
│ Node:              {self.node}
│ Policy requested:  {self.policy_wants}
│ Warrant provides:  {self.warrant_has}
│ Missing authority: {self.missing}
├────────────────────────────────────────────────────────┤
│ Tip: You cannot grant what you do not hold.           │
│      The incoming warrant lacks: {self.missing}        │
╰────────────────────────────────────────────────────────╯
"""
```

Example output:

```
╭─ SecureGraph Policy Violation ─────────────────────────╮
│ Node:              researcher
│ Policy requested:  ['search', 'delete_file']
│ Warrant provides:  ['search', 'read_file']
│ Missing authority: ['delete_file']
├────────────────────────────────────────────────────────┤
│ Tip: You cannot grant what you do not hold.           │
│      The incoming warrant lacks: ['delete_file']       │
╰────────────────────────────────────────────────────────╯
```

---

## Implementation

### Data Structures

```python
@dataclass
class NodePolicy:
    tools: Optional[List[str]] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    terminal: bool = False       # Cannot delegate further
    holds_issuer: bool = False   # Preserves issuer warrant


class AttenuationError(Exception):
    """Base error for attenuation failures."""
    pass


class CycleDetected(AttenuationError):
    """Runtime cycle protection triggered."""
    pass


class ExpiredWarrant(AttenuationError):
    """Warrant TTL exceeded."""
    pass


class DepthExceeded(AttenuationError):
    """Warrant chain depth exceeded max_depth."""
    pass


class InvalidSignature(AttenuationError):
    """Warrant signature verification failed."""
    pass


class UntrustedIssuer(AttenuationError):
    """Warrant does not chain to any trusted root."""
    pass


@dataclass
class AttenuationViolation:
    node: str
    policy_wants: List[str]
    warrant_has: List[str]
    missing: List[str]
    
    def __str__(self) -> str:
        return f"""
╭─ SecureGraph Policy Violation ─────────────────────────╮
│ Node:              {self.node}
│ Policy requested:  {self.policy_wants}
│ Warrant provides:  {self.warrant_has}
│ Missing authority: {self.missing}
├────────────────────────────────────────────────────────┤
│ Tip: You cannot grant what you do not hold.           │
│      The incoming warrant lacks: {self.missing}        │
╰────────────────────────────────────────────────────────╯
"""
```

### SecureGraph Class

```python
class SecureGraph:
    def __init__(
        self,
        graph: StateGraph,
        keypair: SigningKey,
        trusted_roots: List[PublicKey],
        mode: AttenuationMode = AttenuationMode.STRICT,
        verify_on_deserialize: bool = True,
        max_node_visits: int = 10,
    ):
        self._graph = graph
        self._keypair = keypair
        self._trusted_roots = trusted_roots
        self._mode = mode
        self._verify = verify_on_deserialize
        self._max_node_visits = max_node_visits
        self._policies: Dict[str, Optional[NodePolicy]] = {}
        self._deny_unlisted = False
    
    def node(
        self,
        name: str,
        *,
        tools: Optional[List[str]] = None,
        terminal: bool = False,
        holds_issuer: bool = False,
        **constraints,
    ) -> "SecureGraph":
        """Define attenuation policy for a node."""
        if name not in self._graph.nodes:
            raise ConfigurationError(f"Node '{name}' not in graph")
        
        if tools is None and not constraints and not holds_issuer and not terminal:
            # Passthrough Node: Inherits parent warrant unchanged.
            # NOT "full authority" - just no additional narrowing at this node.
            # Authority is still bounded by what the incoming warrant carries.
            self._policies[name] = None
        else:
            self._policies[name] = NodePolicy(
                tools=tools,
                constraints=constraints,
                terminal=terminal,
                holds_issuer=holds_issuer,
            )
        return self
    
    def deny_unlisted(self) -> "SecureGraph":
        """Fail if any node lacks a policy."""
        self._deny_unlisted = True
        return self
    
    def compile(self) -> CompiledGraph:
        """Validate and wrap nodes."""
        self._validate()
        self._wrap_nodes()
        return self._graph.compile()
```

### Validation

```python
def _validate(self) -> None:
    """Check all nodes have policy if deny_unlisted."""
    if self._deny_unlisted:
        missing = set(self._graph.nodes.keys()) - set(self._policies.keys())
        missing -= {"__start__", "__end__"}  # Exclude internal nodes
        if missing:
            raise ConfigurationError(
                f"Nodes missing policy: {missing}. "
                "Add policy or remove deny_unlisted()."
            )
```

### Node Wrapping

```python
def _wrap_nodes(self) -> None:
    """Wrap each node with attenuation logic."""
    for name, fn in list(self._graph.nodes.items()):
        if name in ("__start__", "__end__"):
            continue
        policy = self._policies.get(name)
        self._graph.nodes[name] = self._wrap_node(name, fn, policy)


def _wrap_node(
    self,
    node_name: str,
    fn: Callable,
    policy: Optional[NodePolicy],
) -> Callable:
    """Wrap a single node function."""
    
    async def wrapped(state: Dict[str, Any]) -> Dict[str, Any]:
        # 0. Check cycle limit (runtime protection)
        visits = state.get("__tenuo_visits__", {})
        node_visits = visits.get(node_name, 0)
        
        if node_visits >= self._max_node_visits:
            raise CycleDetected(
                f"Node '{node_name}' visited {node_visits} times. "
                f"Max is {self._max_node_visits}. Possible infinite loop."
            )
        
        visits = {**visits, node_name: node_visits + 1}
        
        # 1. Deserialize AND VERIFY incoming execution warrant
        raw_warrant = state.get("tenuo_warrant")
        if not raw_warrant:
            raise AttenuationError(
                f"Node '{node_name}' received state without tenuo_warrant. "
                "Include tenuo_warrant in initial state."
            )
        
        try:
            parent = Warrant.deserialize(
                raw_warrant,
                trusted_roots=self._trusted_roots if self._verify else None,
            )
        except ExpiredWarrant:
            raise AttenuationError(f"Node '{node_name}' received expired warrant")
        except DepthExceeded:
            raise AttenuationError(f"Node '{node_name}' received warrant exceeding max depth")
        except InvalidSignature:
            raise AttenuationError(f"Node '{node_name}' received tampered warrant")
        except UntrustedIssuer:
            raise AttenuationError(f"Node '{node_name}' received warrant from untrusted issuer")
        
        # 2. Attenuate execution warrant (or pass through)
        if policy is None or (not policy.tools and not policy.constraints and not policy.terminal):
            child = parent
        else:
            child = self._attenuate(parent, policy, node_name)
        
        # 3. Handle issuer warrant
        if policy and policy.holds_issuer:
            issuer = state.get("tenuo_issuer")
        else:
            issuer = None
        
        # 4. Build node's view of state
        node_state = {
            **state,
            "tenuo_warrant": child.serialize(),
            "__tenuo_visits__": visits,
        }
        if issuer:
            node_state["tenuo_issuer"] = issuer
        else:
            node_state.pop("tenuo_issuer", None)  # Strip from workers
        
        # 5. Execute with context (convenience layer for tool protection)
        with warrant_context(child):
            result = await fn(node_state)
        
        # 6. Ensure result is dict
        if not isinstance(result, dict):
            result = {"__result__": result}
        
        # 7. Attach attenuated warrant to outgoing state
        result["tenuo_warrant"] = child.serialize()
        result["__tenuo_visits__"] = visits
        
        # 8. Restore issuer to outgoing state (if supervisor)
        if policy and policy.holds_issuer and "tenuo_issuer" in state:
            result["tenuo_issuer"] = state["tenuo_issuer"]
        
        return result
    
    # Handle sync functions
    if not asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        def sync_wrapped(state: Dict[str, Any]) -> Dict[str, Any]:
            return asyncio.get_event_loop().run_until_complete(wrapped(state))
        return sync_wrapped
    
    return wrapped
```

### Attenuation Logic

```python
def _attenuate(
    self,
    parent: Warrant,
    policy: NodePolicy,
    node_name: str,
) -> Warrant:
    """Attenuate warrant according to policy."""
    granted_tools = None
    
    # Compute tool intersection
    if policy.tools:
        policy_tools = set(policy.tools)
        parent_tools = set(parent.tools) if parent.tools else set()
        granted_tools = policy_tools & parent_tools
        missing = policy_tools - parent_tools
        
        if missing:
            violation = AttenuationViolation(
                node=node_name,
                policy_wants=list(policy_tools),
                warrant_has=list(parent_tools),
                missing=list(missing),
            )
            
            if self._mode == AttenuationMode.STRICT:
                raise AttenuationError(str(violation))
            elif self._mode == AttenuationMode.REPORT_ONLY:
                logger.warning(f"[TENUO] {violation}")
                logger.warning(
                    f"[TENUO] Continuing with {granted_tools} (REPORT_ONLY mode)"
                )
            # INTERSECT mode: silent, just use granted_tools
    
    # Build attenuated warrant
    builder = parent.attenuate()
    
    if granted_tools:
        builder = builder.tools(list(granted_tools))
    
    for key, value in policy.constraints.items():
        builder = builder.constraint(key, value)
    
    if policy.terminal:
        builder = builder.terminal()
    
    return builder.delegate(self._keypair)
```

---

## Conditional Edges

Works naturally — attenuation happens at execution time:

```python
graph.add_conditional_edges(
    "supervisor",
    route_fn,  # Returns "researcher" or "writer"
    {"researcher": "researcher", "writer": "writer"}
)

secure.node("researcher", tools=["search"], path="/data/*")
secure.node("writer", tools=["write_file"], path="/output/*")
```

When `route_fn` returns `"researcher"`, SecureGraph attenuates to researcher's policy. No compile-time knowledge needed.

---

## Cycles

```
supervisor → researcher → supervisor → writer
```

Each transition attenuates and consumes the remaining `max_depth` budget. Multiple defenses apply:

1. **Delegation budget**: Warrant `max_depth` limits total chain length
2. **Expiry**: Warrant `expires_at` prevents long-running cycles
3. **Visit limit**: `max_node_visits` catches runaway loops at runtime

The second supervisor invocation has researcher's attenuated execution warrant, not root.

**But:** If supervisor holds issuer (`holds_issuer=True`), it can mint a fresh execution warrant. The minted warrant still consumes the issuer's remaining `max_depth`, so infinite minting is bounded.

---

## Export for Audit

```python
def export_yaml(self, path: str) -> None:
    """Export policy as YAML for security review."""
    policy = {
        "version": "1",
        "mode": self._mode.value,
        "deny_unlisted": self._deny_unlisted,
        "nodes": {},
    }
    
    for name, node_policy in self._policies.items():
        if node_policy is None:
            policy["nodes"][name] = {"passthrough": True}
        else:
            entry = {}
            if node_policy.tools:
                entry["tools"] = node_policy.tools
            if node_policy.constraints:
                entry["constraints"] = node_policy.constraints
            if node_policy.terminal:
                entry["terminal"] = True
            if node_policy.holds_issuer:
                entry["holds_issuer"] = True
            policy["nodes"][name] = entry or {"passthrough": True}
    
    with open(path, "w") as f:
        yaml.dump(policy, f, sort_keys=False)
```

Output:

```yaml
version: "1"
mode: strict
deny_unlisted: true
nodes:
  supervisor:
    holds_issuer: true
  researcher:
    tools: [search, read_file]
    constraints:
      path: "/data/*"
  writer:
    tools: [write_file]
    constraints:
      path: "/output/*"
```

---

## v0.3 Features (Deferred)

### @policy Decorator

Allows collocated policy definition for rapid development:

```python
# In nodes.py
from tenuo.langgraph import policy

@policy(tools=["search"], path="/data/*")
async def researcher(state):
    ...

# In graph.py
secure = SecureGraph(graph, keypair=keypair)
secure.auto_discover()  # Scrapes @policy decorators
secure.compile()
```

**Important framing for docs:**

> `@policy` decorators are convenient during development. For production, we recommend centralizing policy in your graph definition where security teams can review it in one place.

If both decorator and explicit policy exist, **explicit wins**:

```python
@policy(tools=["search"])  # Ignored
async def researcher(state): ...

secure.node("researcher", tools=["read_file"])  # This takes precedence
```

### Mermaid Visualizer

Generate trust topology for security review:

```python
print(secure.draw_mermaid())
```

Output:

```
graph TD
    supervisor[Supervisor<br/>(holds_issuer)] -->|attenuate| researcher
    researcher[Researcher<br/>(search, read_file)] -->|attenuate| writer
    writer[Writer<br/>(write_file)]
```

### Warrant Compression

For deep graphs, serialized warrant chains grow large. Add external store option:

```python
secure = SecureGraph(
    graph,
    keypair=keypair,
    warrant_store=RedisWarrantStore(redis_client),  # Store warrants externally
)
```

State carries `warrant_ref` instead of full serialized warrant. Defer until chains exceed ~16KB.

---

## Summary

| Principle | How SecureGraph Implements |
|-----------|---------------------------|
| No Amplification | Policy is ceiling, warrant is actual, node gets intersection |
| Cryptographic Integrity | Every warrant verified against `trusted_roots` at each transition |
| Request-Carrying | Warrant travels in `tenuo_warrant`, context is convenience layer |
| Supervisor Authority | `tenuo_issuer` held by supervisors, never attenuates |
| Cycle Protection | `max_depth` (budget), `expires_at`, `max_node_visits` |
| Proof-of-Possession | PoP verified at tool execution boundary |
| Declarative Attenuation | Policy defines shape, SecureGraph calls `attenuate()` |
| Fail-Closed | `deny_unlisted()` + STRICT mode by default |
| Gradual Rollout | REPORT_ONLY mode for production adoption |

---

## Open Questions (Resolved)

| Question | Decision | Rationale |
|----------|----------|-----------|
| State key name | `tenuo_warrant` | Namespace to avoid collision with user's "warrant" objects |
| Multiple warrant types | Single field + type discriminator | Payload has `warrant_type`; keeps state schema simple |
| Compression | Defer to v0.3+ | 1-2KB chains negligible for LLM contexts |
| Supervisor Reset | `tenuo_issuer` held separately | Never attenuates, enables fresh minting |
| Rollout strategy | REPORT_ONLY mode | Log violations without breaking production |
| Cycle protection | Multi-layer defense | `max_depth` (budget, crypto) + `expires_at` (crypto) + `max_node_visits` (runtime) |
| PoP location | Tool execution boundary | Graph is single trust domain; PoP at tool calls |
| SecureGraph trust | Authorized attenuator | Root warrant authorizes SecureGraph's pubkey |
