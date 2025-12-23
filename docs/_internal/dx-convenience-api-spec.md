# Tenuo DX Enhancement Spec: Warrant Convenience API

**Version:** 0.3  
**Status:** Draft  
**Date:** 2025-12-22

---

## TL;DR

**Tenuo = Cryptographic delegation for AI agents.**

Use Tenuo when you need authority that:
- Travels to external services (verifiable offline)
- Survives prompt injection (LLM can't forge signatures)
- Creates audit trails (non-repudiation)

### The Safe Path (Primary API)

```python
# Plain Warrant in state/storage - serializable, no secrets
warrant = receive_warrant_from_orchestrator()

# Explicit key at call site - keys never in state
key = SigningKey.from_env("MY_SERVICE_KEY")
headers = warrant.auth_headers(key, "search", {"query": "test"})

# Explicit key in delegation
child = warrant.delegate(to=worker_pubkey, allow=["search"], ttl=300, key=key)
```

### For Repeated Operations (Advanced)

```python
# BoundWarrant for loops - explicitly non-serializable
bound = warrant.bind_key(key)
for item in items:
    headers = bound.auth_headers("process", {"item": item})
    # ...
# bound should NOT be stored in state/cache
```

### For LangGraph (with Guardrails)

```python
@lockdown(tool="search")  # Auto-registers tool
async def search(query): ...

configure(issuer_key=kp, strict=True, registered_tools="auto")

async with root_task(Capability("search")):
    await graph.compile().ainvoke(state)
```

---

## Security Considerations

### Critical: BoundWarrant Serialization Protection

`BoundWarrant` holds a private key and **must never be serialized**:

```python
class BoundWarrant:  # NOT a Warrant subclass (type separation)
    """Warrant bound to a signing key. Cannot be serialized."""
    
    def __init__(self, warrant: Warrant, key: SigningKey):
        self._warrant = warrant
        self._key = key
    
    # Forwarding: BoundWarrant implements ReadableWarrant by delegation
    @property
    def id(self) -> str: return self._warrant.id
    @property
    def tools(self) -> list[str]: return self._warrant.tools
    @property
    def ttl_remaining(self) -> timedelta: return self._warrant.ttl_remaining
    @property
    def clearance(self) -> Clearance: return self._warrant.clearance
    # ... all other ReadableWarrant properties forwarded
    
    @property
    def warrant(self) -> Warrant:
        """Get the inner warrant (read-only access)."""
        return self._warrant
    
    def unbind(self) -> Warrant:
        """Return the inner warrant without the key."""
        return self._warrant
    
    def bind_key(self, key: SigningKey) -> "BoundWarrant":
        """Return a new BoundWarrant with a different key."""
        return BoundWarrant(self._warrant, key)
    
    def __getstate__(self):
        raise TypeError(
            "BoundWarrant cannot be serialized (contains private key). "
            "Store the Warrant separately and rebind at runtime."
        )
    
    def __reduce__(self):
        raise TypeError("BoundWarrant cannot be pickled")
    
    def __repr__(self):
        return f"<BoundWarrant id={self._warrant.id[:12]}... KEY_BOUND=True>"
```

#### Why BoundWarrant Is NOT a Warrant Subclass

**The Problem:** If `BoundWarrant` inherited from `Warrant`, it could be assigned to `TenuoState.warrant` in LangGraph:

```python
# [NO] DANGEROUS if BoundWarrant(Warrant):
state.warrant = warrant.bind_key(key)  # Type checks pass!
# → LangGraph checkpoints state → Private key serialized to DB!
```

**The Solution:** Separate types prevent this at dev time:

```python
# [OK] SAFE with BoundWarrant as separate type:
state.warrant = warrant.bind_key(key)  # Type error!
# → mypy/pyright catch this before it reaches production
```

This is why `BoundWarrant` **wraps** a `Warrant` instead of inheriting from it.

#### Type Hints for BoundWarrant

Since `BoundWarrant` is not a `Warrant` subclass, provide type hints for functions that accept either:

```python
# In tenuo/types.py
from typing import Protocol, Union

class ReadableWarrant(Protocol):
    """Protocol for warrant-like objects (read-only operations)."""
    @property
    def id(self) -> str: ...
    @property
    def tools(self) -> list[str]: ...
    @property
    def ttl_remaining(self) -> timedelta: ...
    def preview_can(self, tool: str) -> PreviewResult: ...
    def preview_would_allow(self, tool: str, args: dict) -> PreviewResult: ...
    def explain(self) -> str: ...

# For functions that need signing capability
class SignableWarrant(Protocol):
    """Protocol for warrant-like objects that can sign requests."""
    def auth_headers(self, tool: str, args: dict) -> dict[str, str]: ...
    def delegate(self, to: PublicKey, allow: list, ttl: int) -> Warrant: ...

# Union type for convenience
AnyWarrant = Union[Warrant, BoundWarrant]
```

**Usage in SDK:**

```python
def inspect_warrant(warrant: ReadableWarrant) -> None:
    """Works with both Warrant and BoundWarrant."""
    print(warrant.explain())
    for tool in warrant.tools:
        print(f"  {tool}: {warrant.preview_can(tool)}")
```

#### BoundWarrant Usage Examples

**Example 1: Basic Binding and API Calls**

```python
from tenuo import Warrant, SigningKey

# Receive warrant and key separately
warrant = Warrant.from_base64(received_warrant_b64)
key = SigningKey.from_env("WORKER_KEY")

# Bind once, use multiple times
bound = warrant.bind_key(key)

# Make API calls - key is implicit
headers = bound.auth_headers("search", {"query": "test"})
response = requests.get("https://api/search", headers=headers)

headers = bound.auth_headers("read_file", {"path": "/data/report.pdf"})
response = requests.get("https://api/read_file", headers=headers)
```

**Example 2: Delegation with BoundWarrant**

```python
# Orchestrator binds its warrant
orchestrator_bound = orchestrator_warrant.bind_key(orchestrator_key)

# Delegate to workers - signing uses bound key
worker1_warrant = orchestrator_bound.delegate(
    to=worker1_key.public_key,
    allow=["search"],
    ttl=300
)

worker2_warrant = orchestrator_bound.delegate(
    to=worker2_key.public_key,
    allow=["read_file"],
    ttl=300
)

# Workers receive plain Warrants (not BoundWarrant)
# They bind with their own keys
worker1_bound = worker1_warrant.bind_key(worker1_key)
```

**Example 3: Short-Lived Binding (Recommended)**

```python
# DON'T store BoundWarrant in long-lived objects
class MyService:
    def __init__(self, warrant: Warrant, key: SigningKey):
        self.warrant = warrant  # [OK] Store plain Warrant
        self._key = key         # [OK] Store key separately (private)
    
    def call_api(self, tool: str, args: dict):
        # Bind just-in-time for the call
        bound = self.warrant.bind_key(self._key)
        headers = bound.auth_headers(tool, args)
        return requests.post(f"https://api/{tool}", headers=headers, json=args)
```

**Example 4: LangGraph Pattern (Key Registry)**

```python
from tenuo import Warrant
from tenuo.langgraph import KeyRegistry

# Keys stored in registry (not in state!)
registry = KeyRegistry.get_instance()
registry.register("orchestrator", orchestrator_key)
registry.register("worker", worker_key)

# State only holds plain Warrant
class AgentState(TypedDict):
    warrant: Warrant  # [OK] Plain Warrant, safe to checkpoint
    messages: list

async def worker_node(state: AgentState) -> AgentState:
    # Get key from registry at runtime
    key = registry.get("worker")
    bound = state["warrant"].bind_key(key)
    
    # Use bound warrant for API calls
    headers = bound.auth_headers("search", {"query": state["query"]})
    result = await fetch("https://api/search", headers=headers)
    
    return {"messages": state["messages"] + [result]}
```

**Example 5: Testing with BoundWarrant**

```python
import pytest
from tenuo import Warrant, SigningKey
from tenuo.testing import allow_all

def test_api_headers():
    """Test that correct headers are generated."""
    warrant, key = Warrant.quick_issue(tools=["search"], ttl=3600)
    bound = warrant.bind_key(key)
    
    headers = bound.auth_headers("search", {"query": "test"})
    
    assert "X-Tenuo-Warrant" in headers
    assert "X-Tenuo-PoP" in headers

def test_bound_warrant_cannot_serialize():
    """Ensure BoundWarrant raises on serialization attempt."""
    warrant, key = Warrant.quick_issue(tools=["search"], ttl=3600)
    bound = warrant.bind_key(key)
    
    with pytest.raises(TypeError, match="cannot be serialized"):
        import pickle
        pickle.dumps(bound)

def test_bound_warrant_repr_hides_key():
    """Ensure __repr__ doesn't leak the key."""
    warrant, key = Warrant.quick_issue(tools=["search"], ttl=3600)
    bound = warrant.bind_key(key)
    
    repr_str = repr(bound)
    assert "KEY_BOUND=True" in repr_str
    assert str(key) not in repr_str  # Key not in repr
```

**Anti-Pattern: Don't Do This**

```python
# [NO] DON'T store BoundWarrant in state that gets serialized
class BadState(TypedDict):
    bound_warrant: BoundWarrant  # Type error! And dangerous!

# [NO] DON'T pass BoundWarrant across process boundaries
await queue.put(bound_warrant)  # Key would be serialized!

# [NO] DON'T log BoundWarrant (even though __repr__ hides key)
logger.debug(f"Processing with {bound_warrant}")  # Unnecessary risk
```

### Test Utilities Live in `tenuo.testing`

All test-only utilities are isolated in `tenuo.testing` to keep production import paths clean:

```python
# Production code - clean imports
from tenuo import Warrant, SigningKey

# Test code - explicit test imports
from tenuo.testing import deterministic_headers, allow_all, quick_issue
```

| Module | Contains | Purpose |
|--------|----------|---------|
| `tenuo` | `Warrant`, `SigningKey`, `configure`, `lockdown` | Production APIs |
| `tenuo.testing` | `deterministic_headers`, `allow_all`, `quick_issue` | Test-only utilities |

#### `deterministic_headers()` (Test Only)

For unit tests that need to assert exact header values:

```python
from tenuo.testing import deterministic_headers

# Test code - deterministic for assertions
headers = deterministic_headers(warrant, key, "search", {"query": "test"})
assert headers["X-Tenuo-PoP"] == expected_pop  # Stable across runs
```

> **Why not `dry_run()` on BoundWarrant?** Moving test utilities to a separate module makes accidental production use harder. If you import from `tenuo.testing`, it's obvious you're in test code.

### Process-Wide Key Safety

```python
configure(issuer_key=kp)
```

The configured key is **not publicly accessible**:
- No `get_configured_key()` function exposed
- Only internal code (`@lockdown`, `root_task`, `delegate()`) can access
- Key stored in module-level `_config` with no getter

#### [WARNING] `configure()` Is Not a Security Boundary

> **Important:** `configure()` is a *convenience* feature for controlled environments (single-service apps, notebooks, tests). It is NOT a security boundary within a Python process.

**Risks of ambient authority:**
- Plugins, dynamic imports, or injected code can call `@lockdown`-decorated functions
- In multi-tenant apps, wrong tenant's key could be used if not careful
- Notebooks/REPLs may leave keys configured across cells

**Recommended patterns:**

```python
# [OK] RECOMMENDED: Per-service key loading, explicit passing at boundaries
key = SigningKey.from_env("MY_SERVICE_KEY")  # Loaded once at startup
warrant = root_warrant.delegate(to=target, allow=["tool"], key=key)

# [OK] OK: configure() for single-tenant apps with @lockdown/root_task()
configure(issuer_key=kp, strict=True)
with root_task(Capability("tool")):
    await my_tool()  # Uses configured key internally

# [NO] AVOID: configure() for ad-hoc signing outside @lockdown/root_task()
configure(issuer_key=kp)
warrant.delegate(to=x, allow=["tool"])  # Implicit key - harder to audit
```

**Summary:** Use `configure()` when you want `@lockdown` and `root_task()` to work without explicit key passing. For explicit delegation (`delegate()`, `auth_headers()`), prefer passing `key=` explicitly.

### Strict Mode (Fail-Closed)

Prevent forgotten `@lockdown` decorators:

```python
configure(
    issuer_key=kp,
    strict=True,
    registered_tools=["search", "read_file", "delete_file"]
)

# Later, calling unregistered tool raises:
# TenuoConfigError: Tool 'unknown_tool' not registered.
# Add to registered_tools or decorate with @lockdown.
```

### Thread-Safe KeyRegistry

```python
class KeyRegistry:
    _instance: ClassVar[Optional["KeyRegistry"]] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()
    
    @classmethod
    def get_instance(cls) -> "KeyRegistry":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
```

#### Multi-Tenant Namespacing

> [WARNING] **Risk:** In multi-tenant apps, a global registry can accidentally use tenant A's key for tenant B's request.

**Mitigation:** Use namespaced keys:

```python
class KeyRegistry:
    def register(self, key_id: str, key: SigningKey, *, namespace: str = "default"):
        """Register a key with optional namespace."""
        full_id = f"{namespace}:{key_id}"
        self._keys[full_id] = key
    
    def get(self, key_id: str, *, namespace: str = "default") -> SigningKey:
        """Get a key by ID within namespace."""
        full_id = f"{namespace}:{key_id}"
        return self._keys.get(full_id)

# Usage in multi-tenant app:
registry = KeyRegistry.get_instance()

# At tenant onboarding
registry.register("signing", tenant_a_key, namespace="tenant_a")
registry.register("signing", tenant_b_key, namespace="tenant_b")

# At request time (e.g., in FastAPI dependency)
def get_tenant_key(request: Request) -> SigningKey:
    tenant_id = request.headers["X-Tenant-ID"]
    return registry.get("signing", namespace=tenant_id)
```

**Alternative:** Use request-scoped registries via ContextVar:

```python
_request_keys: ContextVar[dict[str, SigningKey]] = ContextVar("request_keys")

@contextmanager
def request_scope(tenant_keys: dict[str, SigningKey]):
    """Set keys for current request only."""
    token = _request_keys.set(tenant_keys)
    try:
        yield
    finally:
        _request_keys.reset(token)

# Usage
with request_scope({"signing": tenant_a_key}):
    # All @tenuo_node calls in this scope use tenant_a_key
    await graph.ainvoke(state)
```

### Logic Consistency: Python Calls Rust

All authorization logic **must** call through to Rust via PyO3:

```python
# [OK] CORRECT: Calls Rust
def preview_would_allow(self, tool: str, args: dict) -> PreviewResult:
    allowed = self._inner.check_constraints(tool, args)  # Rust call
    return PreviewResult(allowed=allowed)

# [NO] WRONG: Python reimplementation (logic divergence risk)
def preview_would_allow(self, tool: str, args: dict) -> PreviewResult:
    for constraint in self.constraints[tool]:
        if not constraint.matches(args):  # Python logic - BAD!
            return PreviewResult(allowed=False)
    return PreviewResult(allowed=True)
```

### ContextVar Limitations

> [WARNING] **Important:** This limitation should also be documented in FastAPI/LangChain integration docs.

`set_warrant_context()` uses Python's `contextvars`. Context propagation works in most cases but has known edge cases:

| [OK] Works | [NO] May Not Work |
|----------|-----------------|
| Standard async/await | `run_in_executor()` without explicit context copy |
| `asyncio.create_task()` | Some third-party async libraries |
| Most LangChain/LangGraph patterns | `multiprocessing` (separate processes) |
| FastAPI dependencies | Thread pools without `copy_context()` |

**Workaround:** For edge cases, use explicit warrant passing or `KeyRegistry`:

```python
# Option 1: Explicit passing (most reliable)
await my_function(warrant=warrant, key=key)

# Option 2: Copy context for executors
import contextvars
ctx = contextvars.copy_context()
await loop.run_in_executor(None, ctx.run, my_sync_function)
```

**Reference:** [Python contextvars asyncio support](https://docs.python.org/3/library/contextvars.html#asyncio-support)

#### Context Helpers (Recommended)

To reduce boilerplate and avoid silent failures, provide explicit helpers:

```python
# tenuo/context.py

import asyncio
import contextvars
from concurrent.futures import Executor
from typing import Callable, TypeVar

T = TypeVar("T")

async def run_in_executor(
    executor: Executor | None,
    fn: Callable[..., T],
    *args,
    **kwargs
) -> T:
    """Run function in executor WITH context propagation."""
    ctx = contextvars.copy_context()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        executor,
        lambda: ctx.run(fn, *args, **kwargs)
    )

def copy_warrant_context() -> contextvars.Context:
    """Copy current context (including warrant). Use for manual propagation."""
    return contextvars.copy_context()
```

**Usage:**

```python
from tenuo.context import run_in_executor

# Instead of:
await loop.run_in_executor(None, blocking_fn)  # [NO] Context lost

# Use:
await run_in_executor(None, blocking_fn)  # [OK] Context preserved
```

#### Guidance for Celery/Multiprocessing

> **[WARNING] ContextVars do NOT propagate across processes.**

For Celery tasks or multiprocessing, **always pass warrants explicitly**:

```python
# [NO] WRONG: Relies on context (will fail)
@celery.task
def process_data():
    warrant = get_current_warrant()  # None in worker process!

# [OK] CORRECT: Pass warrant explicitly
@celery.task
def process_data(warrant_bytes: bytes):
    warrant = Warrant.from_bytes(warrant_bytes)
    with root_task(warrant):
        # Now context is set in worker
        do_work()

# Caller
warrant_bytes = warrant.to_bytes()
process_data.delay(warrant_bytes)
```

### `__repr__` Redaction

Never print keys or signatures in repr/str:

```python
def __repr__(self):
    return f"<Warrant id={self.id[:12]}... tools={self.tools} expires_in={self.ttl_remaining}>"
```

---

## Core Value Proposition

### When Tenuo Provides Real Security Value

Tenuo's value is **cryptographic delegation across trust boundaries**. Simple if-conditions can handle basic access control in trusted, single-process code. Tenuo provides value when:

| Scenario | If-Conditions | Tenuo | Why Tenuo Wins |
|----------|---------------|-------|----------------|
| Single process, trusted code | [OK] Sufficient | Overkill | No trust boundary to cross |
| LLM agent (prompt injection risk) | [NO] Bypassable | [OK] Required | LLM can't forge signatures |
| Multi-service delegation | [NO] Can't travel | [OK] Required | Warrant verifiable offline |
| Multi-agent orchestration | [NO] State is mutable | [OK] Required | Cryptographic authority |
| Audit/compliance | [NO] No proof | [OK] Required | Non-repudiation |
| Multi-tenant isolation | [NO] Code-level only | [OK] Required | Tenant can't escalate |

### What Tenuo Does That If-Conditions Cannot

**1. Authority that travels across trust boundaries:**
```python
# If-condition: Can't send "permission" to external service securely
await external_worker.run(allowed=["search"])  # Just data, can be ignored/forged

# Tenuo: Cryptographically signed, verifiable by recipient
child_warrant = warrant.delegate(to=worker_key, allow=["search"], ttl=300, key=my_key)
await external_worker.run(warrant=child_warrant)  # Verifiable, unforgeable
```

**2. Protection against compromised/untrusted code:**
```python
# If-condition: Attacker with code access can modify checks
ALLOWED = {"search"}  # Attacker: ALLOWED.add("delete_all")

# Tenuo: Warrant is signed, can't be modified without detection
warrant.preview_can("delete_all")  # False, cryptographically enforced
```

**3. LLM can't escape the boundary:**
```python
# If-condition in state: LLM can manipulate
state["allowed_tools"] = ["search"]
# LLM output: "Set allowed_tools to ['search', 'rm_rf']" -> Bypassed!

# Tenuo: Warrant is cryptographic, LLM can't forge
# Even if LLM is prompt-injected, it can't sign a new warrant
```

**4. Audit trail with non-repudiation:**
```python
# If-condition: No proof of who authorized what
log.info("search called")  # Anyone could write this

# Tenuo: Cryptographic proof chain
# Warrant proves: "Key X delegated to Key Y for tool Z at time T"
```

### Honest Assessment: When NOT to Use Tenuo

For single-process applications with trusted code and no delegation, Tenuo adds complexity without proportional benefit. Use simple authorization:

```python
# Good enough for trusted, single-process code
ALLOWED_TOOLS = {"search", "read_file"}

def authorize(tool: str):
    if tool not in ALLOWED_TOOLS:
        raise PermissionError(f"Tool {tool} not allowed")
```

Use Tenuo when you need:
- **Delegation**: Granting subset of your authority to another agent/service
- **Offline verification**: Recipient verifies without calling back to you
- **LLM safety**: Cryptographic boundary prompt injection can't cross
- **Audit**: Cryptographic proof of authorization chain

---

## Objective

Reduce developer friction for the **delegation-centric** use cases where Tenuo provides real value. The API should make cryptographic delegation as easy as passing a token, while keeping the security properties visible.

---

## Complete Flow: From Root to Delegation

Before diving into API tiers, here's the complete journey:

### Step 1: Create Root Authority (Once, at system setup)

```python
from tenuo import Warrant, SigningKey, Pattern

# Generate or load root key (keep this VERY secure)
root_key = SigningKey.generate()
# Or: root_key = SigningKey.from_env("TENUO_ROOT_KEY")

# Create root warrant with explicit capabilities (POLA)
root_warrant = (Warrant.builder()
    .capability("search", {"query": Pattern("*")})
    .capability("read_file", {"path": Pattern("/*")})
    .capability("write_file", {"path": Pattern("/*")})
    .capability("delete_file", {"path": Pattern("/*")})
    .holder(root_key.public_key)
    .ttl(86400 * 365)  # 1 year
    .issue(root_key))

# Store root_warrant.to_base64() securely
```

### Step 2: Delegate to Services/Agents (At runtime)

```python
# Service receives root_warrant (or a delegated warrant) + its own key
service_key = SigningKey.from_env("SERVICE_KEY")
service_warrant = Warrant.from_base64(os.environ["SERVICE_WARRANT"])

# Delegate to a worker agent
worker_key = SigningKey.generate()  # Or load from env
worker_warrant = service_warrant.delegate(
    key=service_key,        # YOU sign the delegation
    to=worker_key.public_key,  # THEY receive it
    allow=["search"],       # Subset of your authority
    ttl=3600,              # 1 hour
)

# Send warrant to worker (they verify offline)
await worker.run(warrant=worker_warrant.to_base64())
```

### Step 3: Worker Uses Warrant

```python
# Worker receives warrant, has their own key
worker_key = SigningKey.from_env("WORKER_KEY")
warrant = Warrant.from_base64(received_warrant_b64)

# Make authorized API calls
headers = warrant.auth_headers(worker_key, "search", {"query": "AI safety"})
response = requests.post("https://api.example.com/search", headers=headers)
```

---

## API Tiers: Complexity Proportional to Security Decision

The API should match complexity to the security decision being made.

### Tier 1: Simple Delegation (Most Common)

```python
# You have: your warrant + your key
# You want: delegate subset to worker

worker_warrant = my_warrant.delegate(
    key=my_key,                # You sign
    to=worker_public_key,      # They receive
    allow=["search", "read_file"],
    ttl=300,
)
```

**Note:** `key` is required because delegation is cryptographic. You're signing a new warrant.

### Tier 2: Constrained Delegation

When you need to restrict HOW tools are used:

```python
from tenuo import Capability, Pattern, Range

worker_warrant = my_warrant.delegate(
    key=my_key,
    to=worker_public_key,
    allow=[
        Capability("search", query=Pattern("*public*"), max_results=Range(max=50)),
        Capability("read_file", path=Pattern("/data/public/*")),
    ],
    ttl=60,
)
```

### Tier 3: Full Control (Rare)

When you need explicit control over every warrant property:

```python
worker_warrant = (my_warrant.attenuate()
    .capability("search", {"query": Pattern("*public*")})
    .capability("read_file", {"path": Pattern("/data/*")})
    .holder(worker_public_key)
    .clearance(Clearance.EXTERNAL)
    .ttl(60)
    .terminal()  # Cannot delegate further
    .delegate(my_key))
```

### Using Bound Keys (Optional Convenience)

If you're doing many operations with the same key:

```python
# Bind once
bound = my_warrant.bind_key(my_key)

# Delegate without repeating key
worker1 = bound.delegate(to=w1_key, allow=["search"], ttl=300)
worker2 = bound.delegate(to=w2_key, allow=["read_file"], ttl=300)

# HTTP headers without repeating key
headers = bound.auth_headers("search", {"query": "test"})
```

### `configure()` for Context-Based Usage

For LangChain/LangGraph apps that use `@lockdown` and `root_task()`, configure the issuer key once:

```python
from tenuo import configure, SigningKey

# At app startup
kp = SigningKey.from_env("TENUO_KEY")
configure(issuer_key=kp)

# Now @lockdown and root_task() can auto-create warrants
@lockdown(tool="search")
async def search(query): ...

async with root_task(Capability("search")):
    await search("test")  # Uses configured key internally
```

**When to use `configure()` vs explicit keys:**

| Approach | Use When |
|----------|----------|
| `configure(issuer_key=...)` | Single-process apps with `@lockdown`/`root_task()` |
| Explicit `key=...` in API calls | Multi-service delegation, explicit control |
| `warrant.bind_key(key)` | Repeated operations with same key |

**Note:** `configure()` sets a process-wide default. It doesn't prevent you from using explicit keys where needed.

### Design Principle

**API complexity should be proportional to the security decision:**

| Decision | Complexity | API |
|----------|------------|-----|
| "Worker gets these tools" | Simple | `delegate(to=pubkey, allow=["tool1"], ttl=300, key=key)` |
| "Worker gets these tools with constraints" | Medium | `delegate(to=pubkey, allow=[Capability(...)], ...)` |
| "Custom warrant with specific properties" | Full | `attenuate().capability()...delegate(key)` |

#### Delegation: One Method, Two Styles

The `delegate()` method works in two ways:

**Direct delegation (most common):**
```python
child = parent.delegate(
    to=worker_pubkey,
    allow=["search"],
    ttl=300,
    key=my_key
)
```

**Builder pattern (for complex attenuation):**
```python
child = (parent.attenuate()
    .capability("search", {"query": Pattern("*public*")})
    .holder(worker_pubkey)
    .clearance(Clearance.EXTERNAL)
    .ttl(300)
    .terminal()
    .delegate(key))  # Same method, called on builder
```

Both use `delegate()` - the difference is whether you call it directly on a warrant or as the final step of a builder chain.


---

## Non-Goals

- New `Client` class (see [Rejected Alternative](#rejected-alternative-tenuoclient))
- Changes to core protocol or wire format
- Breaking changes to existing API

---

## Design Decision: Enhance Warrant vs. New Client

We considered two approaches:

### Option A: New `tenuo.Client` Class (Rejected)

```python
client = Client(key, warrant)
client.auth_headers("tool", args)
client.preview_can("tool")
```

### Option B: Enhance `Warrant` Directly (Chosen)

```python
warrant.auth_headers(key, "tool", args)
warrant.preview_can("tool")
```

### Tradeoff Analysis

| Factor | `Client` Class | Enhanced `Warrant` |
|--------|---------------|-------------------|
| **API Tiers** | 3 tiers (more cognitive load) | 2 tiers (simpler mental model) |
| **Learning Curve** | "Which class do I use?" | Single entry point |
| **Key Binding** | Implicit (passed once) | Explicit (passed each call) |
| **Discoverability** | New class to find | Methods on familiar object |
| **Protocol Fidelity** | Abstracts away PoP | PoP visible in method signature |
| **Testing** | Mock `Client` or `Warrant`? | Just mock `Warrant` |
| **Bundle Size** | Additional code | Minimal addition |

### Why We Chose Option B

1. **Simpler mental model**: Developers learn `Warrant` and that's it. No "should I use Client or Warrant?" confusion.

2. **Protocol transparency**: Seeing `key` in `auth_headers(key, tool, args)` reminds developers that PoP is happening. This is educational, not just ergonomic.

3. **Composability**: Frameworks (FastAPI, LangChain) can wrap `Warrant` directly without an intermediate layer.

4. **Incremental adoption**: Existing code using `Warrant` gains new methods automatically.

### When `Client` Would Be Better

A separate `Client` class would make sense if:

- Key binding happened frequently (it doesn't; most apps have one key)
- We needed stateful operations (connection pooling, caching)
- The abstraction distance from protocol was desirable (it isn't; we want transparency)

### Escape Hatch: `BoundWarrant`

For the rare case where passing `key` repeatedly is tedious:

```python
bound = warrant.bind_key(key)
bound.auth_headers("tool", args)  # No key needed
```

This is opt-in, not the default path.

---

## API Surface

### 1. Introspection Methods

| Method | Returns | Status | Description |
|--------|---------|--------|-------------|
| `warrant.tools` | `list[str]` | [OK] Exists | List of authorized tools |
| `warrant.clearance` | `Clearance \| None` | [OK] Exists | Warrant's clearance level |
| `warrant.depth` | `int` | [OK] Exists | Current delegation depth |
| `warrant.max_depth` | `int` | [OK] Exists | Maximum delegation depth |
| `warrant.issuer` | `PublicKey` | [OK] Exists | Who signed this warrant |
| `warrant.parent_hash` | `str \| None` | [OK] Exists | Hash of parent warrant (if delegated) |
| `warrant.ttl_remaining` | `timedelta` | [NEW] New | Time until expiration |
| `warrant.expires_at` | `datetime` | [NEW] New | Absolute expiration time |
| `warrant.is_terminal` | `bool` | [NEW] New | `depth >= max_depth` (cannot delegate further) |
| `warrant.is_expired` | `bool` | [NEW] New | TTL has elapsed |
| `warrant.capabilities` | `dict[str, dict[str, str]]` | [NEW] New | Human-readable constraints (see below) |

#### `capabilities` Structure

Returns string representations for display/logging (not for programmatic constraint checking):

```python
warrant.capabilities
# {
#     "read_file": {
#         "path": "Pattern('/data/*')",
#         "max_size": "Range(max=1000)"
#     },
#     "search": {
#         "query": "Pattern('*')",
#         "max_results": "Range(max=100)"
#     }
# }
```

**Note:** Values are string representations, not constraint objects. For programmatic access to constraints, use the existing `warrant.get_constraints(tool)` method which returns actual constraint objects.

### 2. Preview Methods (UX Only - NOT Authorization)

| Method | Returns | Raises | Description |
|--------|---------|--------|-------------|
| `warrant.preview_can(tool)` | `PreviewResult` | - | Is tool in warrant? (UX only) |
| `warrant.preview_would_allow(tool, args)` | `PreviewResult` | - | Would args satisfy constraints? (UX only) |

#### `PreviewResult` Type

The return type makes it clear this is NOT authorization:

```python
@dataclass
class PreviewResult:
    """Result of a preview check. NOT AUTHORIZATION."""
    
    allowed: bool
    reason: str | None = None
    
    def __bool__(self) -> bool:
        return self.allowed
    
    def __repr__(self) -> str:
        status = "OK" if self.allowed else "DENIED"
        return f"<PreviewResult {status} (UX ONLY - not authorization)>"

# Usage
result = warrant.preview_can("search")
if result:  # Works as bool
    show_search_button()

# But the repr screams "NOT AUTHORIZATION"
print(result)  # <PreviewResult OK (UX ONLY - not authorization)>
```

> **Why not just `bool`?** A plain `bool` return invites cargo-culting into authorization logic. The explicit type + repr makes misuse more obvious during debugging.

#### Important: These Are NOT For Authorization Logic

Authorization is enforced **at the gateway**, not by the client. Don't do this:

```python
# [NO] WRONG: Client-side authorization check
if warrant.preview_can("read_file"):
    response = requests.post(url, headers=warrant.auth_headers(...))
```

Instead, just call the API. The gateway enforces authorization:

```python
# [OK] RIGHT: Gateway enforces, client handles response
response = requests.post(url, headers=warrant.auth_headers(key, "read_file", args))
if response.status_code == 403:
    error = response.json()
    print(f"Denied: {error['detail']}")
```

#### When To Use `preview_can()` and `preview_would_allow()`

**UX optimization** - show/hide UI elements based on capabilities:

```python
# Gray out buttons for unavailable actions
buttons = [
    Button("Read File", disabled=not warrant.preview_can("read_file")),
    Button("Delete", disabled=not warrant.preview_can("delete_file")),
]

# Pre-validate form before submission (better UX)
if not warrant.preview_would_allow("search", {"query": user_input}):
    show_error("Query too broad for your permissions")
```

**Routing decisions** - choose code paths:

```python
# Route to different implementations based on capabilities
if warrant.preview_can("fast_search"):
    result = fast_search(query)
else:
    result = slow_search(query)
```

> **Note:** These methods are "preview mode" - they check constraints without PoP verification. Real authorization happens at the gateway. The `preview_` prefix and `PreviewResult` return type are intentional to discourage use as authorization gates.

### 3. Debugging ("It's broken, tell me why")

| Method | Returns | Description |
|--------|---------|-------------|
| `warrant.explain()` | `str` | Human-readable warrant summary |
| `warrant.why_denied(tool, args)` | `WhyDenied` | Structured denial explanation |
| `tenuo.explain_request(warrant, tool, args)` | `str` | Full request diagnosis (see below) |

#### `WhyDenied` Structure with Stable Deny Codes

```python
@dataclass
class WhyDenied:
    denied: bool              # True if would be denied
    deny_code: str            # Stable code: "TOOL_NOT_FOUND", "CONSTRAINT_MISMATCH", etc.
    deny_path: str | None     # Dot-path to failure: "constraints.path.pattern_mismatch"
    tool: str                 # The tool that was checked
    field: str | None         # Which constraint field failed (if applicable)
    constraint: Any           # The constraint that rejected (if applicable)
    value: Any                # The value that was rejected (if applicable)
    suggestion: str           # Human-readable fix suggestion
```

**Stable Deny Codes** (machine-readable, for programmatic handling):

| Code | Path Example | Meaning |
|------|--------------|---------|
| `ALLOWED` | - | Request would be allowed |
| `TOOL_NOT_FOUND` | `tool.not_found` | Tool not in warrant |
| `WARRANT_EXPIRED` | `warrant.expired` | Warrant TTL elapsed |
| `CONSTRAINT_MISMATCH` | `constraints.path.pattern_mismatch` | Pattern constraint failed |
| `CONSTRAINT_RANGE` | `constraints.size.out_of_range` | Range constraint failed |
| `CONSTRAINT_MISSING` | `constraints.path.missing_field` | Required field not provided |
| `CLEARANCE_INSUFFICIENT` | `clearance.insufficient` | Tool requires higher clearance |

#### `tenuo.explain_request()` - The Killer Debug Command

```python
import tenuo

# One command to explain everything about a request
print(tenuo.explain_request(warrant, "read_file", {"path": "/etc/passwd"}))
```

Output:
```
Request Analysis
================
Tool: read_file
Args: {"path": "/etc/passwd"}

Warrant Info
------------
ID:      abc123def456...
Issuer:  ed25519:PUBKEY...
TTL:     4m 32s remaining
Tools:   read_file, search

Authorization: DENIED
---------------------
Code:    CONSTRAINT_MISMATCH
Path:    constraints.path.pattern_mismatch
Field:   path
Value:   "/etc/passwd"
Pattern: "/data/*"

Suggestion: Value '/etc/passwd' does not match pattern '/data/*'.
            Allowed paths must start with '/data/'.
```

#### `Unauthorized` Exception with Deny Codes

When authorization fails, exceptions include structured information:

```python
from tenuo import Unauthorized

try:
    await authorized_tool(args)
except Unauthorized as e:
    print(e.deny_code)   # "CONSTRAINT_MISMATCH"
    print(e.deny_path)   # "constraints.path.pattern_mismatch"
    print(e.field)       # "path"
    print(e.suggestion)  # "Value '/etc/passwd' does not match..."
    
    # For logging/metrics
    metrics.increment(f"auth.denied.{e.deny_code}")
```

#### Example Usage

```python
# Tool not in warrant
result = warrant.why_denied("delete_file", {})
# WhyDenied(
#   denied=True,
#   deny_code="TOOL_NOT_FOUND",
#   deny_path="tool.not_found",
#   tool="delete_file",
#   suggestion="Tool 'delete_file' not in warrant. Available: read_file, search"
# )

# Constraint violation
result = warrant.why_denied("read_file", {"path": "/etc/passwd"})
# WhyDenied(
#   denied=True,
#   deny_code="CONSTRAINT_MISMATCH",
#   deny_path="constraints.path.pattern_mismatch",
#   tool="read_file",
#   field="path",
#   constraint=Pattern('/data/*'),
#   value="/etc/passwd",
#   suggestion="Value '/etc/passwd' does not match pattern '/data/*'"
# )

# Would be allowed
result = warrant.why_denied("read_file", {"path": "/data/report.pdf"})
# WhyDenied(denied=False, deny_code="ALLOWED", ...)
```

### 4. HTTP Integration

| Method | Returns | Description |
|--------|---------|-------------|
| `warrant.auth_headers(key, tool, args)` | `dict[str, str]` | Ready-to-use HTTP headers |
| `warrant.sign_request(key, tool, args)` | `tuple[str, str]` | `(warrant_b64, pop_b64)` |

#### Example Usage

```python
# Generate headers for HTTP request
headers = warrant.auth_headers(key, "read_file", {"path": "/data/x.txt"})
# {
#   'X-Tenuo-Warrant': 'gwFZATSr...',
#   'X-Tenuo-PoP': 'MEUCIQD...'
# }


response = requests.post("https://gateway/files/read", headers=headers, json={"path": "/data/x.txt"})
```

### 5. Key Binding (Optional)

For cases where passing `key` every time is tedious:

**On `Warrant`:**

| Method | Returns | Description |
|--------|---------|-------------|
| `warrant.bind_key(key)` | `BoundWarrant` | Returns wrapper with key attached |

**On `BoundWarrant`:**

| Method | Returns | Description |
|--------|---------|-------------|
| `bound.unbind()` | `Warrant` | Returns the inner warrant without key |
| `bound.bind_key(new_key)` | `BoundWarrant` | Returns new wrapper with different key |
| `bound.warrant` | `Warrant` | Get the inner warrant (read-only) |

**Key binding behavior:**
- `bind_key(key)` returns a new `BoundWarrant` wrapper (immutable pattern)
- `BoundWarrant` forwards all read-only properties to the inner `Warrant` (implements `ReadableWarrant`)
- Calling `bind_key(new_key)` on a `BoundWarrant` returns a new wrapper with the new key
- `unbind()` returns the original `Warrant` without any key
- You can always override the bound key by passing `key` explicitly to methods

```python
# Without binding (explicit, recommended for clarity)
headers = warrant.auth_headers(key, "tool", args)

# With binding (convenient for loops)
bound = warrant.bind_key(key)
for item in items:
    headers = bound.auth_headers("process", {"item": item})  # No key needed
    requests.post(url, headers=headers)

# Rebind to a different key
bound = bound.bind_key(other_key)

# Unbind to require explicit key again
unbound = bound.unbind()
headers = unbound.auth_headers(key, "tool", args)  # Must pass key

# Key-bound warrant is still a Warrant (works everywhere)
authorizer.verify(bound)  # Works
bound.attenuate()         # Works
```

#### Implementation Note

`bind_key()` returns a `BoundWarrant` wrapper that behaves identically to the original warrant for read operations, with one enhancement: methods that accept an optional `key` parameter will use the bound key as the default.

```python
class Warrant:
    def bind_key(self, key: SigningKey) -> "BoundWarrant":
        """Return a BoundWarrant wrapper with this warrant and key."""
        return BoundWarrant(self, key)

class BoundWarrant:
    def __init__(self, warrant: Warrant, key: SigningKey):
        self._warrant = warrant
        self._key = key
    
    def auth_headers(self, tool: str, args: dict, *, key: SigningKey | None = None) -> dict:
        """Generate HTTP headers. Uses bound key if key not provided."""
        effective_key = key or self._key
        return self._warrant.auth_headers(tool, args, key=effective_key)
```

This approach:
- `BoundWarrant` is a separate type (not subclass) for serialization safety
- Forwards all read-only properties to inner `Warrant`
- Key binding is explicit opt-in, not the default path

### 6. Delegation

| Method | Returns | Description |
|--------|---------|-------------|
| `warrant.delegate(to, allow, ttl, key)` | `Warrant` | Create child warrant (explicit key) |
| `bound.delegate(to, allow, ttl)` | `Warrant` | Create child warrant (uses bound key) |

**Note:** `delegate()` creates a **new cryptographically signed warrant**. The `to` parameter is the recipient's public key.

#### Example Usage

```python
# Primary API: explicit key at call site
child = parent.delegate(
    to=worker_pubkey,
    allow=["search"],
    ttl=300,
    key=my_signing_key
)

# With BoundWarrant: key implicit
bound = parent.bind_key(my_signing_key)
child = bound.delegate(to=worker_pubkey, allow=["search"], ttl=300)

# allow can be string or list
child = parent.delegate(to=pubkey, allow="search", ttl=300, key=key)          # Single tool
child = parent.delegate(to=pubkey, allow=["search", "read"], ttl=300, key=key) # Multiple
```

#### Delegation Creates New Signed Objects

```python
# This creates a NEW cryptographically signed warrant
child = parent.delegate(to=worker_pubkey, allow=["search"], ttl=300, key=my_key)

# The child is:
# - Signed by my_key (non-forgeable)
# - Attenuated to only "search" (cannot be expanded)
# - Verifiable by anyone with worker_pubkey's public key
# - Independent of parent (can be sent to external service)
```

---

## `explain()` Output Format

```
Warrant Summary
───────────────────────────────────────────────────────
  Type:       Execution
  Tools:      read_file, search
  Clearance:  Internal
  TTL:        4m 32s remaining (expires 2025-12-19 15:30:00 UTC)
  Depth:      2 of 5 (can delegate 3 more times)
  Terminal:   No
  
Capabilities
───────────────────────────────────────────────────────
  read_file:
    path: Pattern('/data/*')
  
  search:
    query: Pattern('*')
    max_results: Range(max=100)
```

---

## Implementation Notes

### Python-Only

These are **Python SDK conveniences**, not Rust core changes. 

Implementation location: `tenuo-python/tenuo/warrant_ext.py`

### Error Messages

Enhanced error messages should include context:

```python
# Before
Unauthorized: constraint violation

# After
Unauthorized: constraint violation for tool 'read_file'
  Field: path
  Constraint: Pattern('/data/*')
  Value: '/etc/passwd'
  Reason: Pattern does not match
```

### Thread Safety

Warrants (including key-bound warrants) are immutable after construction. Safe for concurrent use.

---

## Migration

No migration needed. All new methods are additive.

Existing code continues to work unchanged:

```python
# This still works
pop = warrant.create_pop_signature(key, tool, args)
authorized = warrant.authorize(tool, args, bytes(pop))

# New convenience (optional)
headers = warrant.auth_headers(key, tool, args)
```

---

## Testing Your Code

### Unit Testing with Warrants

```python
import pytest
from tenuo import Warrant, SigningKey, Capability, Pattern

@pytest.fixture
def test_keypair():
    """Generate a fresh keypair for each test."""
    return SigningKey.generate()

@pytest.fixture
def test_warrant(test_keypair):
    """Create a test warrant with known capabilities."""
    return (Warrant.builder()
        .capability("search", {"query": Pattern("*")})
        .capability("read_file", {"path": Pattern("/data/*")})
        .holder(test_keypair.public_key)
        .ttl(3600)
        .issue(test_keypair))

def test_search_authorized(test_warrant, test_keypair):
    """Test that search tool is authorized."""
    headers = test_warrant.auth_headers(test_keypair, "search", {"query": "test"})
    assert "X-Tenuo-Warrant" in headers
    assert "X-Tenuo-PoP" in headers

def test_delete_not_authorized(test_warrant):
    """Test that delete_file is NOT authorized."""
    assert not test_warrant.preview_can("delete_file")
    result = test_warrant.why_denied("delete_file", {})
    assert result.denied
    assert result.reason == "tool_not_found"
```

### Testing with `@lockdown` and `root_task`

```python
import pytest
from tenuo import configure, lockdown, root_task, Capability, SigningKey

@pytest.fixture(autouse=True)
def setup_tenuo():
    """Configure Tenuo for each test."""
    kp = SigningKey.generate()
    configure(issuer_key=kp)
    yield
    # Cleanup happens automatically

@lockdown(tool="search")
async def search(query: str) -> list:
    return [f"Result for {query}"]

@pytest.mark.asyncio
async def test_search_with_authority():
    """Test that search works with proper authority."""
    async with root_task(Capability("search")):
        result = await search("test")
        assert result == ["Result for test"]

@pytest.mark.asyncio
async def test_search_without_authority():
    """Test that search fails without authority."""
    with pytest.raises(Unauthorized):
        await search("test")  # No root_task context
```

### Mocking Warrants (for Integration Tests)

```python
from unittest.mock import Mock, patch

def test_api_with_mocked_warrant():
    """Test API handler without real warrant verification."""
    mock_warrant = Mock()
    mock_warrant.can.return_value = True
    mock_warrant.tools = ["search"]
    
    with patch("myapp.get_warrant_context", return_value=mock_warrant):
        result = my_api_handler({"query": "test"})
        assert result["status"] == "ok"
```

### Testing Delegation

```python
def test_delegation_narrows_scope(test_warrant, test_keypair):
    """Test that delegation reduces capabilities."""
    worker_key = SigningKey.generate()
    
    child = test_warrant.delegate(
        key=test_keypair,
        to=worker_key.public_key,
        allow=["search"],  # Only search, not read_file
        ttl=60,
    )
    
    assert child.preview_can("search")
    assert not child.preview_can("read_file")  # Was narrowed out
```

---

## Documentation Updates

1. **Quickstart**: Rewrite examples to use `auth_headers()` instead of manual PoP construction
2. **API Reference**: Add new methods to Warrant section
3. **Debugging Guide**: New section featuring `explain()` and `why_denied()`
4. **Examples**: Update `basic_usage.py` to demonstrate new methods

---

---

## Framework Integrations

### FastAPI (`tenuo.integrations.fastapi`)

Zero-boilerplate warrant verification for FastAPI endpoints.

#### Core API

```python
from fastapi import FastAPI, Depends
from tenuo.integrations.fastapi import TenuoGuard, SecurityContext

app = FastAPI()

@app.post("/files/read")
async def read_file(
    request: ReadFileRequest,
    ctx: SecurityContext = Depends(TenuoGuard(tool="read_file"))
):
    # If we got here:
    # - X-Tenuo-Warrant header was present and valid
    # - X-Tenuo-PoP signature verified
    # - Warrant authorizes "read_file" tool
    # - Request args satisfy warrant constraints
    
    print(f"Authorized by warrant (Clearance: {ctx.warrant.clearance})")
    return {"content": open(request.path).read()}
```

#### `SecurityContext` Structure

```python
@dataclass
class SecurityContext:
    warrant: Warrant              # The verified warrant
    validated_args: dict          # Request args validated against constraints
    pop_timestamp: datetime       # When PoP was signed (for audit)
    
    # Convenience
    @property
    def clearance(self) -> Clearance:
        """Returns warrant's clearance level, defaulting to Untrusted if None."""
        return self.warrant.clearance or Clearance.Untrusted
    
    @property
    def tools(self) -> list[str]:
        return self.warrant.tools
```

#### `TenuoGuard` Configuration

```python
TenuoGuard(
    tool: str,                              # Required tool (server declares expected tool)
    authorizer: Authorizer = None,          # Custom authorizer, or uses app.state.tenuo_authorizer
    extract_args: Callable[[Request], dict | Awaitable[dict]] = None,  # Sync or async
    on_denied: Callable[[Request, TenuoError], Awaitable[None]] = None,
)
```

**Authorizer Resolution:** If `authorizer` is not provided, `TenuoGuard` looks it up from `app.state.tenuo_authorizer` (set by `configure_tenuo()`). This allows app-wide configuration without passing authorizer to every guard.

#### Argument Extraction

By default, `TenuoGuard` extracts args from:
1. Path parameters
2. Query parameters  
3. JSON body

```python
# Args extracted automatically from request
@app.post("/files/{path}")
async def read_file(
    path: str,                    # From path
    limit: int = 100,             # From query
    ctx: SecurityContext = Depends(TenuoGuard(tool="read_file"))
):
    # ctx.validated_args = {"path": path, "limit": limit}
    pass
```

#### Custom Arg Extraction

```python
# Async extractor (most common)
async def extract_from_body(request: Request) -> dict:
    body = await request.json()
    return {"path": body["file_path"], "limit": body.get("max_lines", 100)}

# Sync extractor also supported
def extract_from_headers(request: Request) -> dict:
    return {"api_key": request.headers.get("X-API-Key")}

@app.post("/files/read")
async def read_file(
    ctx: SecurityContext = Depends(TenuoGuard(
        tool="read_file",
        extract_args=extract_from_body  # Async function
    ))
):
    pass
```

#### Error Handling

**HTTP Status Codes:**

| Condition | Status | Meaning |
|-----------|--------|---------|
| Missing `X-Tenuo-Warrant` header | 401 | Authentication required |
| Invalid warrant (bad signature, expired) | 401 | Authentication failed |
| Invalid PoP signature | 401 | Authentication failed |
| Valid warrant but wrong tool | 403 | Forbidden (authorization) |
| Valid warrant but constraint violation | 403 | Forbidden (authorization) |
| Valid warrant but insufficient clearance | 403 | Forbidden (authorization) |

**Default error response (403 example):**

```python
{
    "error": "forbidden",
    "detail": "constraint violation",
    "tool": "read_file",
    "field": "path",
    "constraint": "Pattern('/data/*')",
    "value": "/etc/passwd"
}
```

**Custom handler:**

```python
async def custom_denied(request: Request, error: TenuoError):
    await audit_log.record(request, error)
    raise HTTPException(status_code=403, detail="Access denied")

TenuoGuard(tool="read_file", on_denied=custom_denied)
```

**Global error handler (alternative):**

```python
from tenuo.integrations.fastapi import TenuoError

@app.exception_handler(TenuoError)
async def tenuo_error_handler(request: Request, exc: TenuoError):
    await audit_log.record(request, exc)
    status = 401 if exc.is_authentication_error else 403
    return JSONResponse(status_code=status, content={"error": str(exc)})
```

#### App-Level Configuration

```python
from tenuo.integrations.fastapi import configure_tenuo

# Configure once at startup
configure_tenuo(
    app,
    authorizer=Authorizer(trusted_roots=[root_key]),
    header_warrant="X-Tenuo-Warrant",      # Default
    header_pop="X-Tenuo-PoP",              # Default
)
```

#### Client Side (Calling Protected Endpoints)

Use the new `auth_headers()` convenience method:

```python
import httpx
from tenuo import SigningKey, Warrant

# Client has a warrant and key
key = SigningKey.from_env("AGENT_KEY")
warrant = Warrant.from_base64(os.environ["AGENT_WARRANT"])

# Call protected endpoint using auth_headers()
args = {"path": "/data/report.pdf"}
headers = warrant.auth_headers(key, "read_file", args)

response = httpx.post(
    "https://api.example.com/files/read",
    headers=headers,
    json=args
)
```

**Headers generated:**
```python
{
    "X-Tenuo-Warrant": "<base64-encoded-warrant>",
    "X-Tenuo-PoP": "<base64-encoded-signature>"
}
```

**Note:** No `X-Tenuo-Tool` header. The server declares the expected tool via `TenuoGuard(tool="read_file")`. The tool name is bound into the PoP signature, so the server verifies the client intended to call the correct endpoint.

**Before (verbose):**
```python
# Manual PoP generation
pop_sig = warrant.create_pop_signature(key, "read_file", args)
headers = {
    "X-Tenuo-Warrant": warrant.to_base64(),
    "X-Tenuo-PoP": base64.b64encode(bytes(pop_sig)).decode(),
}
```

**After (convenience):**
```python
headers = warrant.auth_headers(key, "read_file", args)
```

---

### Flask (Future / On-Demand)

Flask integration is **not in initial scope**. FastAPI covers the majority of new AI agent projects.

For Flask users, manual integration works:

```python
from flask import Flask, request, g
from tenuo import Warrant, Authorizer

app = Flask(__name__)
authorizer = Authorizer(trusted_roots=[root_key])

@app.before_request
def verify_warrant():
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    pop_b64 = request.headers.get("X-Tenuo-PoP")
    
    if warrant_b64:
        g.warrant = Warrant.from_base64(warrant_b64)
        g.pop_sig = base64.b64decode(pop_b64) if pop_b64 else None

@app.route("/files/read", methods=["POST"])
def read_file():
    args = request.json
    authorizer.authorize(g.warrant, "read_file", args, g.pop_sig)
    return open(args["path"]).read()
```

**If demand emerges**, a `tenuo.integrations.flask` module can be added with similar patterns to FastAPI.

---

## Key Management (`tenuo.keys`)

Simple, explicit key loading without magic.

### Core API

```python
from tenuo.keys import Keyring

# From environment variable
keyring = Keyring(
    root=SigningKey.from_env("TENUO_ROOT_KEY")
)

# From file
keyring = Keyring(
    root=SigningKey.from_file("/run/secrets/tenuo-root")
)

# Multiple keys (for rotation)
keyring = Keyring(
    root=SigningKey.from_env("TENUO_ROOT_KEY"),
    previous=[
        SigningKey.from_env("TENUO_ROOT_KEY_V1"),  # Still accepted for verification
    ]
)
```

### `SigningKey` Loading Methods

| Method | Source | Format |
|--------|--------|--------|
| `SigningKey.from_env(name)` | Environment variable | Base64 or hex |
| `SigningKey.from_file(path)` | File path | Raw bytes, Base64, or PEM |
| `SigningKey.from_bytes(data)` | Raw bytes | 32 bytes |
| `SigningKey.from_base64(s)` | Base64 string | Standard base64 |
| `SigningKey.from_hex(s)` | Hex string | 64 hex chars |

### Auto-Detection

`from_env` and `from_file` auto-detect format:

```python
# All of these work:
export TENUO_ROOT_KEY="base64string..."
export TENUO_ROOT_KEY="hexstring..."
export TENUO_ROOT_KEY_FILE="/path/to/key"  # Raw bytes in file
```

### Keyring with Authorizer

```python
keyring = Keyring(root=SigningKey.from_env("TENUO_ROOT_KEY"))

# Use with authorizer
authorizer = Authorizer(trusted_roots=[keyring.root.public_key])

# Use with warrant issuance
warrant = Warrant.issue(keypair=keyring.root, ...)
```

### Key Rotation Pattern

```python
keyring = Keyring(
    root=SigningKey.from_env("TENUO_ROOT_KEY_V2"),      # Current
    previous=[SigningKey.from_env("TENUO_ROOT_KEY_V1")] # Still valid for verify
)

# Authorizer trusts both
authorizer = Authorizer(trusted_roots=keyring.all_public_keys)

# New warrants signed with current key
warrant = Warrant.issue(keypair=keyring.root, ...)

# Old warrants (signed with v1) still verify
authorizer.verify(old_warrant)  # Works
```

### What We DON'T Do

- [NO] No auto-discovery ("look in 5 places automatically")
- [NO] No cloud integrations in core (use `tenuo-aws`, `tenuo-vault` packages)
- [NO] No implicit fallback (explicit `previous` list only)

---

## LangChain Integration (`tenuo.integrations.langchain`)

Protect LangChain tools with automatic warrant verification.

### Tool Protection

```python
from langchain.tools import Tool
from tenuo.integrations.langchain import protect_tool, protect_tools

# Protect a single tool
read_file_tool = Tool(
    name="read_file",
    func=read_file_impl,
    description="Read a file"
)
protected_tool = protect_tool(read_file_tool)

# Protect multiple tools at once
tools = [read_file_tool, search_tool, write_tool]
protected_tools = protect_tools(tools)
```

### How It Works

`protect_tool` wraps the tool's `func` to:
1. Get warrant from context (`get_warrant_context()`)
2. Extract args from tool input
3. Verify warrant authorizes the tool + args
4. Call original function if authorized
5. Raise `Unauthorized` if not

```python
# Under the hood
def protected_func(*args, **kwargs):
    warrant, signing_key = get_warrant_context()
    if warrant is None:
        raise Unauthorized("No warrant in context")
    
    tool_args = extract_args(args, kwargs)
    pop_sig = warrant.create_pop_signature(signing_key, tool_name, tool_args)
    
    # authorize() checks constraints + PoP
    if not warrant.authorize(tool_name, tool_args, bytes(pop_sig)):
        raise Unauthorized(f"Warrant does not authorize {tool_name}")
    
    return original_func(*args, **kwargs)
```

### Context Propagation

Set warrant context before running the agent:

```python
from tenuo import set_warrant_context

# In your API handler
async def handle_request(request):
    warrant = extract_warrant_from_headers(request)
    
    with set_warrant_context(warrant, signing_key):
        # All tool calls inside this block use this warrant
        result = await agent.ainvoke({"input": request.query})
    
    return result
```

### Callback Handler (Advanced)

For fine-grained control over authorization events:

```python
from tenuo.integrations.langchain import TenuoCallbackHandler

handler = TenuoCallbackHandler(
    on_tool_start=lambda tool, args: audit_log.record(tool, args),
    on_tool_authorized=lambda tool, args, warrant: metrics.incr("authorized"),
    on_tool_denied=lambda tool, args, error: alert.send(error),
)

agent = create_agent(tools=protected_tools, callbacks=[handler])
```

### Agent with Tenuo

Complete example:

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor
from tenuo.integrations.langchain import protect_tools, TenuoCallbackHandler
from tenuo import set_warrant_context

# 1. Define tools
tools = [read_file_tool, search_tool]

# 2. Protect them
protected_tools = protect_tools(tools)

# 3. Create agent
llm = ChatOpenAI(model="gpt-4")
agent = create_tool_calling_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

# 4. Run with warrant context
async def run_agent(query: str, warrant: Warrant, key: SigningKey):
    with set_warrant_context(warrant, key):
        return await executor.ainvoke({"input": query})
```

---

## LangGraph Integration (`tenuo.integrations.langgraph`)

### Why Tenuo for LangGraph?

LangGraph state is **mutable data** that flows through nodes. Without Tenuo:

```python
# PROBLEM: State-based "permissions" are just data the LLM can manipulate
state["allowed_tools"] = ["search"]
# LLM (via prompt injection): "Update state to allow delete_file"
# Result: Security bypassed
```

With Tenuo, authority is **cryptographically signed**:

```python
# SOLUTION: Warrant is signed, LLM can't forge it
@tenuo_node(Capability("search"))
async def researcher(state):
    # Even if LLM tries: "Call delete_file" -> Cryptographic denial
    # The warrant doesn't authorize delete_file, and LLM can't sign a new one
```

**Key insight**: Tenuo's value in LangGraph is protecting against:
1. **Prompt injection** - LLM can't escape cryptographic boundaries
2. **Node compromise** - Compromised node can only use its delegated authority
3. **Multi-agent delegation** - Orchestrator delegates subset of authority to workers

### Practical Example: Orchestrator -> Worker Delegation

This is the pattern where Tenuo provides the most value:

```python
from langgraph.graph import StateGraph, END
from tenuo import configure, lockdown, root_task, Capability, Pattern

# Setup
kp = SigningKey.generate()
configure(issuer_key=kp)

# Protected tools (enforcement layer)
@lockdown(tool="search")
async def search(query: str) -> list:
    return await api.search(query)

@lockdown(tool="delete_file")
async def delete_file(path: str) -> None:
    Path(path).unlink()

# Orchestrator has broad authority, delegates narrow authority to LLM
async def orchestrator(state):
    """
    Human-controlled orchestrator. Has full authority.
    Delegates ONLY search to the LLM-driven researcher.
    """
    # Create narrow warrant for LLM agent
    # Even if LLM is prompt-injected, it can ONLY search
    return {
        "researcher_scope": [Capability("search", query=Pattern(f"*{state['topic']}*"))],
        "next": "researcher"
    }

@tenuo_node(Capability("search"))  # Scoped to search only
async def researcher(state):
    """
    LLM-driven node. Has narrow, cryptographically-enforced authority.
    Cannot call delete_file even if prompt-injected.
    """
    results = await search(state["query"])
    # await delete_file("/important")  # DENIED - not in warrant
    return {"results": results}

# Build graph
graph = StateGraph(dict)
graph.add_node("orchestrator", orchestrator)
graph.add_node("researcher", researcher)
graph.add_edge("orchestrator", "researcher")
graph.add_edge("researcher", END)

# Run with root authority
async with root_task(Capability("search"), Capability("delete_file")):
    # Root has both capabilities
    # But researcher only gets search (cryptographically enforced)
    result = await graph.compile().ainvoke({"topic": "AI safety", "query": "AI safety papers"})
```

**What this protects against:**
- Prompt injection telling LLM to "delete all files" - cryptographic denial
- Researcher node code modified to call delete_file - cryptographic denial
- State manipulation to add delete_file - warrant is signed, can't be modified

### The Two-Layer Security Model (Important!)

Tenuo uses TWO layers for LangGraph security:

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: SCOPING (@tenuo_node)                             │
│  - Narrows the warrant BEFORE tool calls                    │
│  - "This node can only use search"                          │
│  - Defense in depth: limits what's even possible            │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: ENFORCEMENT (@lockdown)                           │
│  - Checks warrant at EACH tool call                         │
│  - "Is this specific call authorized?"                      │
│  - The actual security gate                                 │
└─────────────────────────────────────────────────────────────┘
```

**Why two layers?**

| Scenario | @tenuo_node only | @lockdown only | Both |
|----------|------------------|----------------|------|
| Node tries unauthorized tool | [NO] No check | [OK] Denied | [OK] Denied |
| Tool called from wrong node | [OK] Scoped out | [NO] Might allow | [OK] Denied |
| Direct tool import bypass | [NO] No protection | [OK] Denied | [OK] Denied |

**Simple rule**: Use `@lockdown` on ALL tools. Use `@tenuo_node` on nodes that need scoping.

```python
# Layer 2: Enforcement on tools (REQUIRED)
@lockdown(tool="search")
async def search(query: str): ...

@lockdown(tool="delete_file")  
async def delete_file(path: str): ...

# Layer 1: Scoping on nodes (OPTIONAL, for defense in depth)
@tenuo_node(Capability("search"))  # Can ONLY use search
async def researcher(state):
    await search(state["query"])  # OK
    # await delete_file("/x")     # Denied by BOTH layers
```

### Simplest LangGraph Integration

For most apps, you just need:

```python
from tenuo import configure, lockdown, root_task, Capability, SigningKey

# 1. Setup (once at startup)
kp = SigningKey.generate()
configure(issuer_key=kp)

# 2. Protect tools
@lockdown(tool="search")
async def search(query: str) -> list:
    return await api.search(query)

# 3. Define nodes (no @tenuo_node needed for simple cases)
async def researcher(state):
    return {"results": await search(state["query"])}

# 4. Build graph normally
graph = StateGraph(dict)
graph.add_node("researcher", researcher)
# ...

# 5. Run with authority
async with root_task(Capability("search")):
    result = await graph.compile().ainvoke({"query": "test"})
```

Add `@tenuo_node` when you need per-node scoping (defense in depth).

### Integration Guardrails

#### State Validator (Checkpoint Safety)

Validate that state doesn't contain key-bound warrants before checkpointing:

```python
from tenuo.integrations.langgraph import validate_state_for_checkpoint

# In your checkpointer or state hook
def before_checkpoint(state: dict) -> dict:
    """Validate state is safe to checkpoint."""
    validate_state_for_checkpoint(state)  # Raises if BoundWarrant found
    return state

# Or as a graph validator
graph = StateGraph(dict)
graph.set_state_validator(validate_state_for_checkpoint)
```

**Implementation:**

```python
def validate_state_for_checkpoint(state: dict) -> None:
    """
    Validate state contains no BoundWarrant instances.
    Raises TypeError if a BoundWarrant is found (would leak key on checkpoint).
    """
    def check_value(value, path: str):
        if isinstance(value, BoundWarrant):
            raise TypeError(
                f"BoundWarrant found at state['{path}'] - cannot checkpoint. "
                f"Use plain Warrant in state and bind_key() at call site."
            )
        if isinstance(value, dict):
            for k, v in value.items():
                check_value(v, f"{path}.{k}")
        if isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                check_value(v, f"{path}[{i}]")
    
    for key, value in state.items():
        check_value(value, key)
```

#### Strict Mode: `@lockdown` Context Validation

In `strict=True` mode, `@lockdown` can optionally verify it's called within a `root_task()` context:

```python
configure(
    issuer_key=kp,
    strict=True,
    registered_tools="auto",  # Use tools registered by @lockdown
    require_context=True      # @lockdown must be in root_task()
)

# Later...
@lockdown(tool="search")
async def search(query): ...

# [NO] FAILS in strict mode with require_context=True
await search("test")  # Error: search() called outside root_task() context

# [OK] OK
async with root_task(Capability("search")):
    await search("test")
```

#### Auto-Registration via `@lockdown`

Instead of manual tool lists that go stale:

```python
# OLD: Manual list (gets stale)
configure(registered_tools=["search", "read_file", "delete_file"])

# NEW: Auto-registration
@lockdown(tool="search")      # Registers "search" at import time
async def search(query): ...

@lockdown(tool="read_file")   # Registers "read_file" at import time
async def read_file(path): ...

# At startup - use auto-discovered tools
configure(issuer_key=kp, strict=True, registered_tools="auto")
```

**Implementation:**

```python
_registered_tools: set[str] = set()

def lockdown(tool: str):
    """Decorator that protects a tool function and registers it."""
    _registered_tools.add(tool)  # Auto-register at import time
    
    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            # ... enforcement logic ...
        return wrapper
    return decorator

def configure(*, registered_tools: list[str] | Literal["auto"] = "auto", ...):
    if registered_tools == "auto":
        registered_tools = list(_registered_tools)
    # ...
```

### Key Management in LangGraph

> **Note**: For most use cases, `configure(issuer_key=...)` with a single shared key is sufficient. Per-node keys (KeyRegistry) are only needed for:
> - Multi-organization workflows (different orgs sign with different keys)
> - Audit requirements (cryptographic attribution per node)
> - Blast radius containment (compromised node can't sign as another)

> [WARNING] **Security Warning**: Never pass `SigningKey` through graph state. Keys could be logged, serialized, or leaked.

#### Why This Matters

LangGraph state can be:
- **Logged** by observability tools (LangSmith, etc.)
- **Serialized** to checkpoints for resumption
- **Passed** to LLMs as context in some architectures
- **Leaked** via error messages or debug output

Private keys in state = potential key compromise.

#### Pattern 1: Key Registry (Recommended)

A singleton registry holds keys; nodes reference by ID.

```python
from tenuo.integrations.langgraph import KeyRegistry

# === SETUP (once at application startup) ===

key_registry = KeyRegistry()

# Load keys from secure sources
key_registry.register("orchestrator", SigningKey.from_env("ORCHESTRATOR_KEY"))
key_registry.register("researcher", SigningKey.from_env("RESEARCHER_KEY"))
key_registry.register("writer", SigningKey.from_file("/run/secrets/writer-key"))

# === NODE DEFINITION ===

@tenuo_node(tool="search", key_id="researcher")
async def research_node(state: AgentState):
    # Decorator looks up key from registry
    # Key is NEVER in state
    results = await search(state.task)
    return {"messages": state.messages + [results]}
```

#### `KeyRegistry` API

```python
class KeyRegistry:
    """Thread-safe registry for signing keys."""
    
    _instance: ClassVar["KeyRegistry"] = None
    
    @classmethod
    def get_instance(cls) -> "KeyRegistry":
        """Get the global registry (singleton)."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def register(self, key_id: str, key: SigningKey) -> None:
        """Register a key with an ID."""
        self._keys[key_id] = key
    
    def get(self, key_id: str) -> SigningKey:
        """Get a key by ID. Raises KeyError if not found."""
        return self._keys[key_id]
    
    def get_public(self, key_id: str) -> PublicKey:
        """Get only the public key (safe to pass around)."""
        return self._keys[key_id].public_key
    
    def has(self, key_id: str) -> bool:
        """Check if a key is registered."""
        return key_id in self._keys
    
    def clear(self) -> None:
        """Clear all keys (for testing)."""
        self._keys.clear()
```

#### `@tenuo_node` Decorator Implementation

```python
def tenuo_node(tool: str, key_id: str | None = None):
    """Decorator that adds Tenuo authorization to a LangGraph node."""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(state: TenuoState, *args, **kwargs):
            warrant = state.get("warrant")
            if warrant is None:
                raise Unauthorized("No warrant in state")
            
            # Get key from registry (NOT from state)
            if key_id:
                key = KeyRegistry.get_instance().get(key_id)
            else:
                raise ValueError("key_id required for @tenuo_node")
            
            # Extract args for authorization
            tool_args = extract_tool_args(state, func)
            
            # Create PoP and verify
            pop_sig = warrant.create_pop_signature(key, tool, tool_args)
            if not warrant.authorize(tool, tool_args, bytes(pop_sig)):
                raise Unauthorized(f"Warrant does not authorize {tool}")
            
            # Call the actual node function
            # Optionally inject key for delegation scenarios
            if "key" in inspect.signature(func).parameters:
                return await func(state, key=key, *args, **kwargs)
            else:
                return await func(state, *args, **kwargs)
        
        return wrapper
    return decorator
```

#### Pattern 2: Inject via Config (Alternative)

For simpler graphs with a single key:

```python
# Keys passed in config, not state
result = await app.ainvoke(
    {"query": "AI safety", "warrant": warrant},
    config={"configurable": {"signing_key": key}}
)

# Node accesses via get_config()
@tenuo_node(tool="search")
async def search_node(state: AgentState, config: RunnableConfig):
    key = config["configurable"]["signing_key"]
    # ...
```

**Tradeoff:** Config is still passed through the system, but it's:
- Not part of state (not checkpointed)
- Not logged by default
- Clearly separated from data

#### Pattern 3: Per-Invocation Key Callback (Advanced)

For dynamic key selection:

```python
def get_key_for_node(node_name: str, state: TenuoState) -> SigningKey:
    """Dynamic key selection based on context."""
    if state.warrant.clearance >= Clearance.PRIVILEGED:
        return high_clearance_key
    else:
        return low_clearance_key

graph = TenuoGraph(
    state_schema=AgentState,
    key_provider=get_key_for_node,  # Called per-node
)
```

#### Security Comparison

| Approach | Key in State? | Checkpointed? | Logged? | Recommendation |
|----------|--------------|---------------|---------|----------------|
| `KeyRegistry` | [NO] No | [NO] No | [NO] No | [OK] **Recommended** |
| Config injection | [NO] No | [NO] No | [WARNING] Maybe | [OK] OK for simple cases |
| State field | [OK] Yes | [OK] Yes | [OK] Yes | [NO] **Never do this** |

### Warrant Attenuation in Graph

Delegate narrower warrants as you traverse the graph:

```python
@tenuo_node(tool="orchestrate", key_id="orchestrator")
async def orchestrator_node(state: AgentState, key: SigningKey):
    # Key injected by decorator, not from state
    research_warrant = (state.warrant.attenuate()
        .capability("search", {"query": Pattern(f"*{state.task}*")})
        .holder(key_registry.get("researcher").public_key)
        .ttl(60)
        .terminal()
        .delegate(key))  # Injected key, not state.signing_key
    
    # Only warrant flows through state (not the key)
    return {
        **state,
        "warrant": research_warrant,
        "next_node": "research"
    }
```

**Note:** The current API requires explicit `.holder()` and `.capability()` calls (POLA). No `inherit_all()` - you must specify what capabilities to grant.

### Graph-Level Policy

Apply authorization rules to the entire graph:

```python
from tenuo.integrations.langgraph import TenuoGraph

graph = TenuoGraph(
    state_schema=AgentState,
    authorizer=authorizer,
    # Require minimum clearance for entire graph
    min_clearance=Clearance.INTERNAL,
)

# Or per-node requirements
graph.add_node("research", research_node, requires_tool="search")
graph.add_node("write", write_node, requires_clearance=Clearance.PRIVILEGED)
```

### Conditional Edges with Authorization

```python
def route_by_authorization(state: AgentState) -> str:
    """Route based on what the warrant allows."""
    if state.warrant.preview_can("write_file"):
        return "write_results"
    elif state.warrant.preview_can("summarize"):
        return "summarize_only"
    else:
        return "read_only"

graph.add_conditional_edges("process", route_by_authorization)
```

### Complete LangGraph Example

```python
from langgraph.graph import StateGraph, END
from tenuo.integrations.langgraph import tenuo_node, TenuoState, KeyRegistry

# Setup key registry (once at startup)
key_registry = KeyRegistry()
key_registry.register("agent", agent_key)

class ResearchState(TenuoState):
    query: str
    sources: list
    summary: str

@tenuo_node(tool="search", key_id="agent")
async def search_node(state: ResearchState):
    results = await web_search(state.query)
    return {"sources": results}

@tenuo_node(tool="summarize", key_id="agent")
async def summarize_node(state: ResearchState):
    summary = await llm_summarize(state.sources)
    return {"summary": summary}

# Build graph
graph = StateGraph(ResearchState)
graph.add_node("search", search_node)
graph.add_node("summarize", summarize_node)
graph.add_edge("search", "summarize")
graph.add_edge("summarize", END)

# Compile and run
app = graph.compile()

# Run with warrant (key NOT in state - looked up from registry)
result = await app.ainvoke({
    "query": "AI safety research",
    "warrant": warrant,
    # No signing_key here! Looked up via key_id="agent"
})
```

---

## Design Decisions (Resolved)

1. **Header names**: Use `X-Tenuo-Warrant` and `X-Tenuo-PoP`.
   - Aligns with existing code
   - Avoids conflicts with standard `Authorization` header
   - Semantically correct: "Warrant" is a complex object, not a simple token

## Open Questions

1. **`why_denied()` depth**: Should it check the full constraint tree or stop at first failure?

2. **`capabilities` format**: Return constraint objects or string representations?

---

---

## Implementation Plan

### Phase 1: Warrant Convenience Methods (Foundation)
**Effort:** 3-4 days | **Priority:** P0 | **Dependencies:** None

#### 1.1 Core Properties

| Task | File | Effort |
|------|------|--------|
| Add `ttl_remaining` property (returns `timedelta`) | `warrant_ext.py` | 0.5h |
| Add `expires_at` property (returns `datetime`) | `warrant_ext.py` | 0.5h |
| Add `is_terminal` property (`depth >= max_depth`) | `warrant_ext.py` | 0.5h |
| Add `is_expired` property | `warrant_ext.py` | 0.5h |
| Add `preview_can(tool)` returning `PreviewResult` | `warrant_ext.py` | 1h |
| Add `preview_would_allow(tool, args)` returning `PreviewResult` (calls Rust) | `warrant_ext.py` | 2h |

#### 1.2 Debugging & Introspection

| Task | File | Effort |
|------|------|--------|
| Add `explain()` method (formatted string) | `warrant_ext.py` | 3h |
| Add `explain(include_chain=True)` for full authority chain | `warrant_ext.py` | 2h |
| Add `inspect()` alias for `explain()` (pretty tree output) | `warrant_ext.py` | 1h |
| Add `why_denied(tool, args)` with `WhyDenied` dataclass | `warrant_ext.py` | 4h |
| Add `parent.diff(child)` exposure via `DelegationDiff` | `warrant_ext.py` | 1h |
| Implement `__repr__` redaction (no keys/signatures) | `warrant_ext.py` | 0.5h |

#### 1.3 Delegation

| Task | File | Effort |
|------|------|--------|
| Add `delegate(to, allow, ttl, key)` - creates signed child warrant | `warrant_ext.py` | 3h |
| Support `allow` as string or list (`allow="search"` or `allow=["a","b"]`) | `warrant_ext.py` | 1h |
| Add improved error messages with fix suggestions | `warrant_ext.py` | 2h |

#### 1.4 BoundWarrant (Security-Critical)

| Task | File | Effort |
|------|------|--------|
| Implement `BoundWarrant` class (NOT a Warrant subclass) | `warrant_ext.py` | 2h |
| Add `__getstate__` / `__reduce__` serialization guards | `warrant_ext.py` | 1h |
| Add `Warrant.bind_key(key)` returning `BoundWarrant` | `warrant_ext.py` | 1h |
| Add `BoundWarrant.unbind()` returning inner `Warrant` | `warrant_ext.py` | 0.5h |
| Add `BoundWarrant.warrant` property (read-only) | `warrant_ext.py` | 0.5h |
| Forward all `ReadableWarrant` properties to inner warrant | `warrant_ext.py` | 1h |

#### 1.5 Prototyping & Testing Utilities

| Task | File | Effort |
|------|------|--------|
| Add `tenuo.testing.deterministic_headers(warrant, key, tool, args)` | `testing.py` | 2h |
| Add `Warrant.quick_issue(tools, ttl)` returns `(warrant, key)` | `warrant_ext.py` | 1h |
| Add `Warrant.for_testing(tools)` with runtime guard | `testing.py` | 1h |
| Add `tenuo.testing.allow_all()` context manager with safety latch | `testing.py` | 2h |
| Implement `_is_test_environment()` check | `testing.py` | 1h |

**Safety Latch for `allow_all()`:**

```python
@contextmanager
def allow_all():
    """Bypass authorization for testing. NEVER ships to production."""
    # Safety latch: fail hard in production
    if os.getenv("TENUO_ENV") == "production":
        raise SecurityError(
            "allow_all() is disabled in production! "
            "Set TENUO_ENV to 'development' or 'test' to use testing utilities."
        )
    if not _is_test_environment():
        raise RuntimeError(
            "allow_all() only works in test environments. "
            "Set TENUO_TEST_MODE=1 or run under pytest."
        )
    # ... bypass authorization
```

#### 1.6 Diagnostics

| Task | File | Effort |
|------|------|--------|
| Add `tenuo.diagnose(warrant)` troubleshooting output | `diagnostics.py` | 3h |
| Add `tenuo.info()` configuration status | `diagnostics.py` | 1h |

#### 1.7 Tests & Docs

| Task | File | Effort |
|------|------|--------|
| Unit tests for all methods | `tests/test_warrant_convenience.py` | 4h |
| Unit tests for BoundWarrant serialization guards | `tests/test_bound_warrant.py` | 2h |
| Update API reference documentation | `docs/api-reference.md` | 2h |

**Deliverable:** Enhanced `Warrant` class with all convenience methods and security guards.

---

### Phase 2: Key Management & Configuration (`tenuo.keys`, `tenuo.config`)
**Effort:** 2-3 days | **Priority:** P1 | **Dependencies:** None (parallel with Phase 1)

#### 2.1 Key Loading

| Task | File | Effort |
|------|------|--------|
| Create `tenuo/keys.py` module | `tenuo/keys.py` | - |
| Implement `SigningKey.from_env(name)` with format auto-detect | `keys.py` | 2h |
| Implement `SigningKey.from_file(path)` with format auto-detect | `keys.py` | 2h |
| Implement `Keyring` class (root + previous keys) | `keys.py` | 2h |
| Add `keyring.all_public_keys` property | `keys.py` | 0.5h |

#### 2.2 Configuration

| Task | File | Effort |
|------|------|--------|
| Implement `configure(issuer_key, strict, registered_tools, dev_mode)` | `config.py` | 2h |
| No public `get_configured_key()` - internal access only | `config.py` | - |
| Implement strict mode validation | `config.py` | 2h |
| Thread-safe `KeyRegistry` singleton with double-checked locking | `keys.py` | 2h |

#### 2.3 Tests & Docs

| Task | File | Effort |
|------|------|--------|
| Unit tests for key loading | `tests/test_keys.py` | 2h |
| Unit tests for strict mode | `tests/test_config.py` | 2h |
| Documentation | `docs/api-reference.md` | 1h |

**Deliverable:** Simple, explicit key loading with strict mode for fail-closed security.

---

### Phase 3: FastAPI Integration
**Effort:** 3-4 days | **Priority:** P0 | **Dependencies:** Phase 1

| Task | File | Effort |
|------|------|--------|
| Create `tenuo/integrations/fastapi.py` | `integrations/fastapi.py` | - |
| Implement `SecurityContext` dataclass | `fastapi.py` | 1h |
| Implement `TenuoGuard` dependency | `fastapi.py` | 4h |
| - Header extraction (warrant + PoP) | | |
| - Authorizer lookup from app state | | |
| - Arg extraction (path/query/body) | | |
| - Custom arg extraction support (sync + async) | | |
| Implement `configure_tenuo(app, ...)` | `fastapi.py` | 1h |
| Implement error handling (401 vs 403) | `fastapi.py` | 2h |
| Implement `TenuoError` exception with `is_authentication_error` | `fastapi.py` | 1h |
| Unit tests (mock FastAPI app) | `tests/test_fastapi_integration.py` | 4h |
| Integration tests (real FastAPI app) | `tests/test_fastapi_e2e.py` | 3h |
| Example: `examples/fastapi_protected.py` | `examples/` | 2h |
| Documentation | `docs/integrations/fastapi.md` | 2h |

**Deliverable:** Zero-boilerplate FastAPI integration.

---

### Phase 4: LangChain Integration
**Effort:** 2-3 days | **Priority:** P1 | **Dependencies:** Phase 1

| Task | File | Effort |
|------|------|--------|
| Create `tenuo/integrations/langchain.py` | `integrations/langchain.py` | - |
| Implement `protect_tool(tool)` wrapper | `langchain.py` | 3h |
| Implement `protect_tools(tools)` batch wrapper | `langchain.py` | 1h |
| Implement `set_warrant_context()` context manager | `langchain.py` | 2h |
| Implement `get_warrant_context()` | `langchain.py` | 0.5h |
| Implement `TenuoCallbackHandler` | `langchain.py` | 3h |
| Unit tests | `tests/test_langchain_integration.py` | 3h |
| Example: `examples/langchain_protected.py` | `examples/` | 2h |
| Documentation | `docs/integrations/langchain.md` | 2h |

**Deliverable:** Protected LangChain tools with context propagation.

---

### Phase 5: LangGraph Integration
**Effort:** 3-4 days | **Priority:** P2 | **Dependencies:** Phase 1, Phase 4

| Task | File | Effort |
|------|------|--------|
| Create `tenuo/integrations/langgraph.py` | `integrations/langgraph.py` | - |
| Implement `TenuoState` base class | `langgraph.py` | 1h |
| Implement `KeyRegistry` singleton | `langgraph.py` | 3h |
| Implement `@tenuo_node` decorator | `langgraph.py` | 4h |
| - Key lookup from registry | | |
| - Tool args extraction | | |
| - Authorization check | | |
| - Optional key injection for delegation | | |
| Implement `TenuoGraph` wrapper (optional) | `langgraph.py` | 3h |
| Unit tests | `tests/test_langgraph_integration.py` | 4h |
| Example: `examples/langgraph_protected.py` | `examples/` | 3h |
| Documentation | `docs/integrations/langgraph.md` | 2h |

**Deliverable:** Secure LangGraph integration with KeyRegistry pattern.

---

### Phase 6: Documentation & Polish
**Effort:** 2 days | **Priority:** P1 | **Dependencies:** All phases

| Task | Effort |
|------|--------|
| Rewrite Quickstart with new patterns | 3h |
| Add "Debugging" guide (`explain()`, `why_denied()`) | 2h |
| Update all examples to use convenience API | 3h |
| Review and update API reference | 2h |
| Add integration guides to docs site navigation | 1h |
| Changelog entry | 0.5h |

---

### Timeline Summary

```
Week 1:
  Phase 1: Warrant Convenience (P0) -------->
  Phase 2: Key Management (P1) ----->

Week 2:
  Phase 3: FastAPI Integration (P0) -------->
  Phase 4: LangChain Integration (P1) -------->

Week 3:
  Phase 5: LangGraph Integration (P2) -------->
  Phase 6: Documentation (P1) -------->
```

**Total estimated effort:** 12-16 days (2-3 weeks with buffer)

---

### Risk Mitigation

#### Security Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Poisoned Checkpoint** - BoundWarrant serialized to DB | High | `BoundWarrant` not a `Warrant` subclass + `__getstate__` throws |
| **Forgotten @lockdown** - Unprotected tool callable | High | `strict=True` mode with `registered_tools` allowlist |
| **Process-wide key access** - Unintended code accesses key | Medium | No public `get_configured_key()`, internal access only |
| **Logic divergence** - Python/Rust constraint mismatch | Medium | All Python convenience methods call Rust via PyO3 |
| **Key in __repr__** - Key leaked to logs | Medium | Custom `__repr__` with redaction |
| **KeyRegistry race condition** | Low | Double-checked locking with `threading.Lock` |
| **ContextVar propagation** - Context lost in executor | Medium | Document limitations, recommend explicit passing |

#### Technical Risks

| Risk | Mitigation |
|------|------------|
| FastAPI version compatibility | Test against FastAPI 0.100+ (Pydantic v2) |
| LangChain API changes | Pin to langchain-core, avoid langchain meta-package |
| LangGraph is new/unstable | Keep integration minimal, document version requirements |
| Breaking existing API | All additions are new methods, no changes to existing |

---

### Success Metrics

- [ ] Quickstart code reduced by 50%+ lines
- [ ] Zero manual PoP generation in examples
- [ ] All integration tests pass on CI
- [ ] `why_denied()` provides actionable error messages
- [ ] No private keys in LangGraph state (enforced by design)
- [ ] `BoundWarrant` serialization attempt raises `TypeError`
- [ ] Strict mode catches unregistered tools at runtime
- [ ] All `preview_would_allow()` / constraint checks call Rust (no Python reimplementation)

---

## Acceptance Criteria

### Warrant Convenience Methods
- [ ] `ttl_remaining` returns `timedelta`
- [ ] `expires_at` returns `datetime`
- [ ] `is_terminal` returns `bool` (`depth >= max_depth`)
- [ ] `is_expired` returns `bool`
- [ ] `preview_can(tool)` returns `PreviewResult` (UX introspection only)
- [ ] `preview_would_allow(tool, args)` returns `PreviewResult` (calls Rust)
- [ ] `explain()` returns formatted string
- [ ] `explain(include_chain=True)` shows full authority chain
- [ ] `inspect()` alias for `explain()` with tree output
- [ ] `why_denied(tool, args)` returns `WhyDenied` with `.code`, `.field`, `.expected`, `.received`
- [ ] `parent.diff(child)` returns `DelegationDiff`
- [ ] `__repr__` never prints keys or signatures

### Delegation
- [ ] `delegate(to, allow, ttl, key)` - creates new signed child warrant
- [ ] `allow` accepts string or list (`allow="search"` or `allow=["a","b"]`)
- [ ] Error messages include fix suggestions

### BoundWarrant (Security-Critical)
- [ ] `BoundWarrant` is NOT a `Warrant` subclass
- [ ] `Warrant.bind_key(key)` returns `BoundWarrant`
- [ ] `BoundWarrant.unbind()` returns the inner `Warrant`
- [ ] `BoundWarrant.warrant` property returns inner `Warrant` (read-only)
- [ ] `BoundWarrant.bind_key(new_key)` returns new `BoundWarrant` with different key
- [ ] `BoundWarrant` forwards all `ReadableWarrant` properties to inner warrant
- [ ] `BoundWarrant.__getstate__()` raises `TypeError`
- [ ] `BoundWarrant.__reduce__()` raises `TypeError`
- [ ] `BoundWarrant.__repr__()` shows `KEY_BOUND=True`, not the key

### Prototyping & Testing
- [ ] `tenuo.testing.deterministic_headers(warrant, key, tool, args)` for test assertions
- [ ] `Warrant.quick_issue(tools, ttl)` returns `(warrant, key)`
- [ ] `Warrant.for_testing(tools)` raises outside test environment
- [ ] `tenuo.testing.allow_all()` raises outside test environment
- [ ] `tenuo.testing.allow_all()` raises `SecurityError` when `TENUO_ENV=production`
- [ ] `_is_test_environment()` detects pytest/TENUO_TEST_MODE

### Type Hints
- [ ] `ReadableWarrant` protocol for read-only warrant operations
- [ ] `SignableWarrant` protocol for signing operations
- [ ] `AnyWarrant = Union[Warrant, BoundWarrant]` type alias

### Configuration
- [ ] `configure(issuer_key, strict, registered_tools)` sets process-wide config
- [ ] No public `get_configured_key()` function
- [ ] `strict=True` raises on unregistered tool access
- [ ] `KeyRegistry` is thread-safe (double-checked locking)

### Diagnostics
- [ ] `tenuo.diagnose(warrant)` shows validity, expiry, chain issues
- [ ] `tenuo.info()` shows current configuration status

### FastAPI Integration
- [ ] `TenuoGuard` dependency extracts and verifies warrant
- [ ] `SecurityContext` provides warrant and validated args
- [ ] Auto-extraction from path/query/body
- [ ] Custom arg extraction support
- [ ] Custom error handler support
- [ ] `configure_tenuo()` app-level setup
- [ ] 401/403 responses with structured error body

### Key Management
- [ ] `SigningKey.from_env(name)` with auto-detect
- [ ] `SigningKey.from_file(path)` with auto-detect
- [ ] `Keyring` with root and previous keys
- [ ] `keyring.all_public_keys` for authorizer setup

### LangChain Integration
- [ ] `protect_tool()` wraps single tool
- [ ] `protect_tools()` wraps multiple tools
- [ ] Context propagation via `set_warrant_context()`
- [ ] `TenuoCallbackHandler` for audit/metrics

### LangGraph Integration
- [ ] `@tenuo_node` decorator for node authorization
- [ ] `TenuoState` base class (warrant only, NO signing_key)
- [ ] `KeyRegistry` for secure key management
- [ ] Warrant attenuation pattern documented
- [ ] `TenuoGraph` with graph-level policy (optional)
- [ ] Conditional routing by authorization
- [ ] Security warning about keys in state

### General
- [ ] Unit tests for all new methods
- [ ] Quickstart updated with new patterns
- [ ] API reference updated
- [ ] FastAPI example in `examples/`
- [ ] LangChain example in `examples/`
- [ ] LangGraph example in `examples/`

---

## Appendix: Full Example

### Basic Usage with New DX

```python
from tenuo import SigningKey, Warrant, configure

# Setup - configure once
key = SigningKey.generate()
configure(issuer_key=key, strict=True, registered_tools=["search", "read_file"])

# Receive warrant from orchestrator
warrant = receive_warrant_from_orchestrator()

# Introspection
print(warrant.explain(include_chain=True))
print(f"Tools: {warrant.tools}")
print(f"Expires in: {warrant.ttl_remaining}")
print(f"Can delegate: {not warrant.is_terminal}")

# Quick tool check (UX only - not authorization!)
if warrant.preview_can("read_file"):
    print("UI: read_file button enabled")

# Delegate to worker (explicit key - recommended)
worker_warrant = warrant.delegate(
    to=worker_public_key,
    allow=["read_file"],  # Or allow="read_file" for single tool
    ttl=300,
    key=key
)

# Make the call - gateway enforces authorization
args = {"path": "/data/report.pdf"}
headers = worker_warrant.auth_headers(worker_key, "read_file", args)
response = requests.get("https://gateway/read_file", headers=headers)

if response.status_code == 403:
    # Use why_denied() to understand the failure
    result = warrant.why_denied("read_file", args)
    print(f"Denied: {result.code}")
    print(f"Field: {result.field}")
    print(f"Expected: {result.expected}")
    print(f"Received: {result.received}")
    print(f"Suggestion: {result.suggestion}")
else:
    print(f"Success: {response.json()}")
```

### Prototyping (Dev Only)

```python
from tenuo import Warrant

# Quick start for demos - NOT for production!
warrant, key = Warrant.quick_issue(tools=["search", "read_file"], ttl=3600)

# Testing utilities (only work in test environment)
from tenuo.testing import allow_all

def test_my_function():
    with allow_all():
        # Authorization bypassed for testing
        result = my_protected_function()
```

### Troubleshooting

```python
import tenuo

# Check configuration
tenuo.info()
# Output:
# Tenuo Configuration
# ├── Issuer Key: Configured [OK]
# ├── Dev Mode: False
# ├── Strict Mode: True
# ├── Registered Tools: search, read_file
# └── Default TTL: 300s

# Diagnose a warrant
tenuo.diagnose(warrant)
# Output:
# Warrant Status: [WARNING] Issues Found
#
# [OK] Signature: Valid
# [OK] Chain: Valid (depth 2)
# [NO] Expired: 3 minutes ago
#
# Suggestion: Warrant has expired. Request a fresh warrant from the issuer.
```
