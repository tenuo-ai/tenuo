# Kubernetes Flow vs Normal Agentic Workflow - Coexistence Pattern

## Key Insight: Same Code, Different Warrant Sources

The authorization logic is **identical** across all environments. Only the warrant loading mechanism differs.

## The Unified Pattern

### Your Application Code (Same Everywhere)

```python
from tenuo import lockdown, set_warrant_context

# Tool functions are IDENTICAL in all environments
@lockdown(tool="read_file", extract_args=lambda file_path, **kwargs: {"file_path": file_path})
def read_file(file_path: str) -> str:
    """This code works the same in K8s, local dev, cloud functions, etc."""
    with open(file_path, 'r') as f:
        return f.read()

# Agent code is IDENTICAL
def run_agent(prompt: str, warrant: Warrant):
    with set_warrant_context(warrant):  # ← Only warrant source differs
        agent_executor.invoke({"input": prompt})
```

### Warrant Loading Abstraction

Create a unified warrant loader that works everywhere:

```python
def get_warrant() -> Optional[Warrant]:
    """
    Unified warrant loader - works in all environments.
    
    Priority:
    1. Kubernetes sources (if running in K8s)
    2. Local development sources
    3. Create new warrant (for testing)
    """
    # Try Kubernetes sources first
    warrant = (
        load_warrant_from_file("/etc/tenuo/warrant.b64") or  # K8s volume mount
        load_warrant_from_env() or                            # K8s Secret env var
        None
    )
    
    # Fall back to local development sources
    if not warrant:
        warrant = (
            load_warrant_from_file("~/.tenuo/warrant.b64") or  # Local file
            Warrant.from_base64(os.getenv("TENUO_WARRANT")) or  # Local env var
            None
        )
    
    # For testing/development, create a warrant if none found
    if not warrant and os.getenv("TENUO_CREATE_IF_MISSING") == "true":
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="agent_tools",
            constraints={"file_path": Pattern("/tmp/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
    
    return warrant
```

## Environment-Specific Patterns

### Kubernetes (Production)

```python
# Init container fetches warrant, writes to /etc/tenuo/warrant.b64
# Main container loads at startup

from tenuo import Warrant, set_warrant_context

def load_warrant_from_file(path: str = "/etc/tenuo/warrant.b64") -> Optional[Warrant]:
    with open(path, 'r') as f:
        return Warrant.from_base64(f.read().strip())

# Application startup
warrant = load_warrant_from_file()
if not warrant:
    raise RuntimeError("No warrant available - init container should have fetched it")

with set_warrant_context(warrant):
    app.run()  # FastAPI/LangChain app
```

### Local Development

```python
# Load from env var or create locally for testing

from tenuo import Warrant, Pattern, Keypair, set_warrant_context

def get_warrant() -> Warrant:
    # Try env var first
    if os.getenv("TENUO_WARRANT"):
        return Warrant.from_base64(os.getenv("TENUO_WARRANT"))
    
    # Create for local testing
    keypair = Keypair.generate()
    return Warrant.create(
        tool="agent_tools",
        constraints={"file_path": Pattern("/tmp/*")},
        ttl_seconds=3600,
        keypair=keypair
    )

# Application startup
warrant = get_warrant()
with set_warrant_context(warrant):
    app.run()  # Same FastAPI/LangChain app
```

### Cloud Functions / Serverless

```python
# Load from environment or request context

from tenuo import Warrant, set_warrant_context

def get_warrant_from_request(request) -> Optional[Warrant]:
    # Try request header
    if "X-Tenuo-Warrant" in request.headers:
        return Warrant.from_base64(request.headers["X-Tenuo-Warrant"])
    
    # Fall back to function environment
    return Warrant.from_base64(os.getenv("TENUO_WARRANT"))

# Function handler
def handler(request):
    warrant = get_warrant_from_request(request)
    if not warrant:
        return {"error": "No warrant"}, 403
    
    with set_warrant_context(warrant):
        return agent_executor.invoke({"input": request.json["prompt"]})
```

## Complete Example: Works Everywhere

```python
#!/usr/bin/env python3
"""
Unified Tenuo + LangChain Example
Works in: Kubernetes, Local Dev, Cloud Functions, etc.
"""

from tenuo import (
    Warrant, Pattern, Keypair,
    lockdown, set_warrant_context, AuthorizationError
)
from langchain.agents import AgentExecutor
import os

# ============================================================================
# Tool Functions (IDENTICAL everywhere)
# ============================================================================

@lockdown(tool="read_file", extract_args=lambda file_path, **kwargs: {"file_path": file_path})
def read_file(file_path: str) -> str:
    """Same code in all environments."""
    with open(file_path, 'r') as f:
        return f.read()

# ============================================================================
# Warrant Loading (Environment-aware)
# ============================================================================

def get_warrant() -> Warrant:
    """Unified warrant loader - works everywhere."""
    # 1. Try Kubernetes sources
    if os.path.exists("/etc/tenuo/warrant.b64"):
        with open("/etc/tenuo/warrant.b64", 'r') as f:
            return Warrant.from_base64(f.read().strip())
    
    # 2. Try environment variable
    if os.getenv("TENUO_WARRANT_BASE64"):
        return Warrant.from_base64(os.getenv("TENUO_WARRANT_BASE64"))
    
    # 3. Create for local development/testing
    keypair = Keypair.generate()
    return Warrant.create(
        tool="agent_tools",
        constraints={"file_path": Pattern("/tmp/*")},
        ttl_seconds=3600,
        keypair=keypair
    )

# ============================================================================
# Application Code (IDENTICAL everywhere)
# ============================================================================

def main():
    # Load warrant (source depends on environment)
    warrant = get_warrant()
    
    # Use warrant (same code everywhere)
    with set_warrant_context(warrant):
        # All @lockdown functions work the same
        agent_executor.invoke({"input": "Read /tmp/test.txt"})

if __name__ == "__main__":
    main()
```

## Key Takeaways

1. **Same Code**: `@lockdown` decorators and tool functions are identical
2. **Different Sources**: Only warrant loading differs by environment
3. **Unified Pattern**: Abstract warrant loading behind a function
4. **Easy Testing**: Create warrants locally, load from K8s in production
5. **ContextVar Works Everywhere**: Async/await compatible in all environments

## Migration Path

1. **Start Local**: Use `Warrant.create()` for development
2. **Add Abstraction**: Create `get_warrant()` function
3. **Add K8s Support**: Check for `/etc/tenuo/warrant.b64` first
4. **Deploy to K8s**: Init container writes warrant, code loads it
5. **No Code Changes**: Same application code works everywhere

