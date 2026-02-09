# Tenuo × OpenAI Examples

Examples demonstrating Tenuo integration with OpenAI's API and Agents SDK.

## Quick Start

```bash
# Install dependencies
uv pip install tenuo openai

# Set API key
export OPENAI_API_KEY="sk-..."

# Run examples
python guardrails.py    # Tier 1: Runtime guardrails
python warrant.py       # Tier 2: Cryptographic authorization
python async_patterns.py  # Async/streaming patterns
python agents_sdk.py    # Agents SDK integration
```

## Examples

### [guardrails.py](guardrails.py) - Tier 1 Protection

Runtime guardrails without warrants. Shows:
- `GuardBuilder` API for constraint definition
- Constraint types: `Subpath`, `UrlSafe`, `Range`, etc.
- Denial modes (block, monitor, audit)
- Streaming protection
- Audit logging

**Use when**: You want immediate protection without cryptographic overhead.

### [warrant.py](warrant.py) - Tier 2 Protection

Full cryptographic authorization with warrants. Shows:
- Warrant creation and binding
- Proof-of-Possession (PoP) signatures
- Key separation (issuer vs holder)
- Constraint enforcement at crypto level
- `client.validate()` for verification

**Use when**: You need delegation, audit trails, or theft-resistance.

### [async_patterns.py](async_patterns.py) - Async Patterns

Async client wrapping and streaming. Shows:
- Async OpenAI client with Tenuo
- Streaming with TOCTOU protection
- Concurrent authorization
- Error handling in async context

**Use when**: Building async applications or using streaming APIs.

### [agents_sdk.py](agents_sdk.py) - Agents SDK Integration

Using Tenuo with OpenAI's Agents SDK. Shows:
- `create_tier1_guardrail()` helper
- `create_tier2_guardrail()` with warrants
- Agent + guardrail integration
- Multi-turn conversations with protection

**Use when**: Using OpenAI's Agents SDK (Swarm, etc.).

### [database_protection.py](database_protection.py) - Database Tool Protection

Protecting AI agent database access using structured tools. Shows:
- `OneOf` for table and operation allow-lists
- `Subset` for column access control
- `Range` for result set limits
- Zero-trust rejection of unknown arguments
- Warrant delegation with attenuation
- Audit trail for every DB access attempt
- Current limitations (no `SqlSafe` semantic constraint)

**Use when**: You need to give AI agents database access safely.

## Security Constraints

These examples demonstrate common security constraints:

| Constraint | Protection |
|------------|------------|
| `Subpath("/data")` | Blocks path traversal (`../`, symlinks) |
| `UrlSafe()` | Blocks SSRF (private IPs, metadata endpoints) |
| `Range(0, 100)` | Bounds numeric values |
| `OneOf([...])` | Allowlist pattern |
| `Regex(...)` | Pattern matching |

## Learn More

- [Tenuo Documentation](https://tenuo.ai)
- [OpenAI API Reference](https://platform.openai.com/docs)
- [Main Examples README](../README.md)
