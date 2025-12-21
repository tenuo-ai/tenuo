# Tenuo DX Enhancement Spec: Warrant Convenience API

**Version:** 0.1  
**Status:** Draft  
**Date:** 2025-12-19

---

## Objective

Reduce developer friction by adding convenience methods to `Warrant` without introducing a new abstraction layer.

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
client.can("tool")
```

### Option B: Enhance `Warrant` Directly (Chosen)

```python
warrant.auth_headers(key, "tool", args)
warrant.can("tool")
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
| `warrant.tools` | `list[str]` | ✅ Exists | List of authorized tools |
| `warrant.trust_level` | `TrustLevel \| None` | ✅ Exists | Warrant's trust level |
| `warrant.depth` | `int` | ✅ Exists | Current delegation depth |
| `warrant.max_depth` | `int` | ✅ Exists | Maximum delegation depth |
| `warrant.issuer` | `PublicKey` | ✅ Exists | Who signed this warrant |
| `warrant.parent_hash` | `str \| None` | ✅ Exists | Hash of parent warrant (if delegated) |
| `warrant.ttl_remaining` | `timedelta` | 🆕 New | Time until expiration |
| `warrant.expires_at` | `datetime` | 🆕 New | Absolute expiration time |
| `warrant.is_terminal` | `bool` | 🆕 New | `depth >= max_depth` (cannot delegate further) |
| `warrant.is_expired` | `bool` | 🆕 New | TTL has elapsed |
| `warrant.capabilities` | `dict[str, dict[str, str]]` | 🆕 New | Human-readable constraints (see below) |

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

### 2. Introspection Methods (UX Only)

| Method | Returns | Raises | Description |
|--------|---------|--------|-------------|
| `warrant.can(tool)` | `bool` | - | Is tool in warrant? |
| `warrant.would_allow(tool, args)` | `bool` | - | Would args satisfy constraints? |

These are **hypothetical checks** for UX purposes. They do NOT perform authorization.

#### Important: These Are NOT For Authorization Logic

Authorization is enforced **at the gateway**, not by the client. Don't do this:

```python
# ❌ WRONG: Client-side authorization check
if warrant.can("read_file"):
    response = requests.post(url, headers=warrant.auth_headers(...))
```

Instead, just call the API. The gateway enforces authorization:

```python
# ✅ RIGHT: Gateway enforces, client handles response
response = requests.post(url, headers=warrant.auth_headers(key, "read_file", args))
if response.status_code == 403:
    error = response.json()
    print(f"Denied: {error['detail']}")
```

#### When To Use `can()` and `would_allow()`

**UX optimization** - show/hide UI elements based on capabilities:

```python
# Gray out buttons for unavailable actions
buttons = [
    Button("Read File", disabled=not warrant.can("read_file")),
    Button("Delete", disabled=not warrant.can("delete_file")),
]

# Pre-validate form before submission (better UX)
if not warrant.would_allow("search", {"query": user_input}):
    show_error("Query too broad for your permissions")
```

**Routing decisions** - choose code paths:

```python
# Route to different implementations based on capabilities
if warrant.can("fast_search"):
    result = fast_search(query)
else:
    result = slow_search(query)
```

**Note:** These methods are "preview mode" - they check constraints without PoP verification. Real authorization happens at the gateway.

### 3. Debugging

| Method | Returns | Description |
|--------|---------|-------------|
| `warrant.explain()` | `str` | Human-readable warrant summary |
| `warrant.why_denied(tool, args)` | `WhyDenied` | Structured denial explanation |

#### `WhyDenied` Structure

```python
@dataclass
class WhyDenied:
    denied: bool          # True if would be denied
    reason: str           # "allowed" | "tool_not_found" | "constraint_violation" | "expired"
    tool: str             # The tool that was checked
    field: str | None     # Which constraint field failed (if applicable)
    constraint: Any       # The constraint that rejected (if applicable)
    value: Any            # The value that was rejected (if applicable)
    suggestion: str       # Human-readable fix suggestion
```

#### Example Usage

```python
# Tool not in warrant
result = warrant.why_denied("delete_file", {})
# WhyDenied(
#   denied=True,
#   reason="tool_not_found",
#   tool="delete_file",
#   suggestion="Tool 'delete_file' not in warrant. Available: read_file, search"
# )

# Constraint violation
result = warrant.why_denied("read_file", {"path": "/etc/passwd"})
# WhyDenied(
#   denied=True,
#   reason="constraint_violation",
#   tool="read_file",
#   field="path",
#   constraint=Pattern('/data/*'),
#   value="/etc/passwd",
#   suggestion="Value '/etc/passwd' does not match pattern '/data/*'"
# )

# Would be allowed
result = warrant.why_denied("read_file", {"path": "/data/report.pdf"})
# WhyDenied(denied=False, reason="allowed", ...)
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
#   'X-Tenuo-PoP': 'MEUCIQD...',
#   'X-Tenuo-Tool': 'read_file'
# }

response = requests.post("https://gateway/invoke", headers=headers, json=args)
```

### 5. Key Binding (Optional)

For cases where passing `key` every time is tedious:

| Method | Returns | Description |
|--------|---------|-------------|
| `warrant.bind_key(key)` | `Warrant` | Returns warrant with key attached |

```python
# Without binding (explicit, recommended)
headers = warrant.auth_headers(key, "tool", args)

# With binding (convenient for loops)
bound = warrant.bind_key(key)
for item in items:
    headers = bound.auth_headers("process", {"item": item})  # No key needed
    requests.post(url, headers=headers)

# Key-bound warrant is still a Warrant (works everywhere)
authorizer.verify(bound)  # ✅ Works
bound.attenuate()         # ✅ Works
```

#### Implementation Note

`bind_key()` returns a warrant that behaves identically to the original, with one enhancement: methods that accept an optional `key` parameter will use the bound key as the default.

```python
class Warrant:
    _bound_key: SigningKey | None = None
    
    def bind_key(self, key: SigningKey) -> "Warrant":
        """Return a copy of this warrant with a key attached."""
        bound = self._copy()
        bound._bound_key = key
        return bound
    
    def auth_headers(self, key: SigningKey | None = None, tool: str, args: dict) -> dict:
        """Generate HTTP headers. Uses bound key if key not provided."""
        effective_key = key or self._bound_key
        if effective_key is None:
            raise ValueError("key required (or use bind_key() first)")
        # ...
```

This approach:
- No new type to document or learn
- Bound warrant passes `isinstance(w, Warrant)` checks
- All existing code works unchanged
- Key binding is just "a warrant with a key attached"

---

## `explain()` Output Format

```
Warrant Summary
───────────────────────────────────────────────────────
  Type:       Execution
  Tools:      read_file, search
  Trust:      Internal
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
    # ✓ X-Tenuo-Warrant header was present and valid
    # ✓ X-Tenuo-PoP signature verified
    # ✓ Warrant authorizes "read_file" tool
    # ✓ Request args satisfy warrant constraints
    
    print(f"Authorized by warrant (Trust: {ctx.warrant.trust_level})")
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
    def trust_level(self) -> TrustLevel:
        """Returns warrant's trust level, defaulting to Untrusted if None."""
        return self.warrant.trust_level or TrustLevel.Untrusted
    
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
| Valid warrant but insufficient trust level | 403 | Forbidden (authorization) |

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
authorizer.verify(old_warrant)  # ✓ Works
```

### What We DON'T Do

- ❌ No auto-discovery ("look in 5 places automatically")
- ❌ No cloud integrations in core (use `tenuo-aws`, `tenuo-vault` packages)
- ❌ No implicit fallback (explicit `previous` list only)

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

Node-level authorization for LangGraph workflows.

### Protected Nodes

```python
from langgraph.graph import StateGraph
from tenuo.integrations.langgraph import tenuo_node, TenuoState

# Define state with warrant
class AgentState(TenuoState):
    messages: list
    task: str

# Protect a node
@tenuo_node(tool="research")
async def research_node(state: AgentState):
    # Only runs if state.warrant authorizes "research"
    results = await search(state.task)
    return {"messages": state.messages + [results]}

# Build graph
graph = StateGraph(AgentState)
graph.add_node("research", research_node)
graph.add_node("summarize", summarize_node)
graph.add_edge("research", "summarize")
```

### `TenuoState` Base Class

```python
class TenuoState(TypedDict):
    """Base state that carries warrant context through the graph."""
    warrant: Warrant | None
    # NOTE: We do NOT store signing_key in state (security risk)
```

Your state extends this:

```python
class MyState(TenuoState):
    messages: list
    current_task: str
    results: dict
```

### Key Management in LangGraph

> ⚠️ **Security Warning**: Never pass `SigningKey` through graph state. Keys could be logged, serialized, or leaked.

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
    if state.warrant.trust_level >= TrustLevel.Privileged:
        return high_trust_key
    else:
        return low_trust_key

graph = TenuoGraph(
    state_schema=AgentState,
    key_provider=get_key_for_node,  # Called per-node
)
```

#### Security Comparison

| Approach | Key in State? | Checkpointed? | Logged? | Recommendation |
|----------|--------------|---------------|---------|----------------|
| `KeyRegistry` | ❌ No | ❌ No | ❌ No | ✅ **Recommended** |
| Config injection | ❌ No | ❌ No | ⚠️ Maybe | ✅ OK for simple cases |
| State field | ✅ Yes | ✅ Yes | ✅ Yes | ❌ **Never do this** |

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
    # Require minimum trust level for entire graph
    min_trust_level=TrustLevel.Internal,
)

# Or per-node requirements
graph.add_node("research", research_node, requires_tool="search")
graph.add_node("write", write_node, requires_trust=TrustLevel.Privileged)
```

### Conditional Edges with Authorization

```python
def route_by_authorization(state: AgentState) -> str:
    """Route based on what the warrant allows."""
    if state.warrant.can("write_file"):
        return "write_results"
    elif state.warrant.can("summarize"):
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
**Effort:** 2-3 days | **Priority:** P0 | **Dependencies:** None

| Task | File | Effort |
|------|------|--------|
| Add `ttl_remaining` property (returns `timedelta`) | `warrant_ext.py` | 0.5h |
| Add `expires_at` property (returns `datetime`) | `warrant_ext.py` | 0.5h |
| Add `is_terminal` property (`depth >= max_depth`) | `warrant_ext.py` | 0.5h |
| Add `is_expired` property | `warrant_ext.py` | 0.5h |
| Add `capabilities` property (dict of string representations) | `warrant_ext.py` | 2h |
| Add `can(tool)` method | `warrant_ext.py` | 1h |
| Add `would_allow(tool, args)` method | `warrant_ext.py` | 2h |
| Add `explain()` method (formatted string) | `warrant_ext.py` | 3h |
| Add `why_denied(tool, args)` with `WhyDenied` dataclass | `warrant_ext.py` | 4h |
| Add `auth_headers(key, tool, args)` method | `warrant_ext.py` | 2h |
| Add `sign_request(key, tool, args)` method | `warrant_ext.py` | 1h |
| Add `bind_key(key)` returning key-bound warrant | `warrant_ext.py` | 2h |
| Unit tests for all methods | `tests/test_warrant_convenience.py` | 4h |
| Update API reference documentation | `docs/api-reference.md` | 2h |

**Deliverable:** Enhanced `Warrant` class with all convenience methods.

---

### Phase 2: Key Management (`tenuo.keys`)
**Effort:** 1-2 days | **Priority:** P1 | **Dependencies:** None (parallel with Phase 1)

| Task | File | Effort |
|------|------|--------|
| Create `tenuo/keys.py` module | `tenuo/keys.py` | - |
| Implement `SigningKey.from_env(name)` with format auto-detect | `keys.py` | 2h |
| Implement `SigningKey.from_file(path)` with format auto-detect | `keys.py` | 2h |
| Implement `Keyring` class (root + previous keys) | `keys.py` | 2h |
| Add `keyring.all_public_keys` property | `keys.py` | 0.5h |
| Unit tests | `tests/test_keys.py` | 2h |
| Documentation | `docs/api-reference.md` | 1h |

**Deliverable:** Simple, explicit key loading without magic.

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
├── Phase 1: Warrant Convenience (P0) ────────────────►
├── Phase 2: Key Management (P1) ─────────►
│
Week 2:
├── Phase 3: FastAPI Integration (P0) ────────────────────────►
├── Phase 4: LangChain Integration (P1) ──────────────►
│
Week 3:
├── Phase 5: LangGraph Integration (P2) ──────────────────────►
├── Phase 6: Documentation (P1) ──────────────────────►
```

**Total estimated effort:** 12-16 days (2-3 weeks with buffer)

---

### Risk Mitigation

| Risk | Mitigation |
|------|------------|
| FastAPI version compatibility | Test against FastAPI 0.100+ (Pydantic v2) |
| LangChain API changes | Pin to langchain-core, avoid langchain meta-package |
| LangGraph is new/unstable | Keep integration minimal, document version requirements |
| Key registry thread safety | Use `threading.Lock` or `contextvars` |
| Breaking existing API | All additions are new methods, no changes to existing |

---

### Success Metrics

- [ ] Quickstart code reduced by 50%+ lines
- [ ] Zero manual PoP generation in examples
- [ ] All integration tests pass on CI
- [ ] `why_denied()` provides actionable error messages
- [ ] No private keys in LangGraph state (enforced by design)

---

## Acceptance Criteria

### Warrant Convenience Methods
- [ ] `ttl_remaining` returns `timedelta`
- [ ] `expires_at` returns `datetime`
- [ ] `is_terminal` returns `bool` (`depth >= max_depth`)
- [ ] `is_expired` returns `bool`
- [ ] `capabilities` returns readable dict
- [ ] `can(tool)` returns `bool` (UX introspection)
- [ ] `would_allow(tool, args)` returns `bool` (UX introspection)
- [ ] `explain()` returns formatted string
- [ ] `why_denied(tool, args)` returns `WhyDenied`
- [ ] `auth_headers(key, tool, args)` returns header dict
- [ ] `sign_request(key, tool, args)` returns tuple
- [ ] `bind_key(key)` returns key-bound `Warrant`
- [ ] Key-bound warrant passes `isinstance(w, Warrant)`

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

```python
from tenuo import SigningKey, Warrant

# Setup
key = SigningKey.generate()
warrant = receive_warrant_from_orchestrator()

# Introspection
print(warrant.explain())
print(f"Tools: {warrant.tools}")
print(f"Expires in: {warrant.ttl_remaining}")
print(f"Can delegate: {not warrant.is_terminal}")

# Make the call - gateway enforces authorization
args = {"path": "/data/report.pdf"}
headers = warrant.auth_headers(key, "read_file", args)
response = requests.get("https://gateway/read_file", headers=headers)

if response.status_code == 403:
    # Use why_denied() to understand the failure
    result = warrant.why_denied("read_file", args)
    print(f"Denied: {result.suggestion}")
else:
    print(f"Success: {response.json()}")
```
