# Tenuo CrewAI Examples

This directory contains basic examples demonstrating Tenuo's CrewAI integration.

> **Looking for the full interactive demo?** See [`tenuo-python/examples/crewai/`](../../tenuo-python/examples/crewai/) for the comprehensive demo with real LLM integration and attack simulations.

## Examples

### 1. Basic Protection (`basic_protection.py`)

Tier 1 constraint-based protection for CrewAI tools. Demonstrates:
- Creating guards with the builder pattern
- Using semantic constraints (Subpath, Pattern, Range)
- Handling denied tool calls
- Guard introspection and validation

```bash
python basic_protection.py
```

### 2. Hierarchical Delegation (`hierarchical_delegation.py`)

Tier 2 warrant delegation for hierarchical crews. Demonstrates:
- Creating warrants for manager agents
- Using `WarrantDelegator` to delegate to workers
- Attenuation-only delegation (narrowing scope)
- Escalation prevention
- Using seal mode to prevent bypass

```bash
python hierarchical_delegation.py
```

## Quick Start

```python
from tenuo.crewai import GuardBuilder, Subpath, Pattern

# Create guard
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .allow("search", query=Pattern("*"))
    .build())

# Protect tools
protected_read = guard.protect(read_file_tool)
protected_search = guard.protect(search_tool)

# Use in CrewAI agent
agent = Agent(
    role="Researcher",
    tools=[protected_read, protected_search],
)
```

## See Also

- [Full Documentation](../../docs/crewai.md)
