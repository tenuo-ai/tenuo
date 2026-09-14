# Tenuo × LangChain Examples

Examples demonstrating Tenuo integration with LangChain and LangGraph.

## Quick Start

```bash
# Install dependencies
uv pip install "tenuo[langchain]" langchain-openai langchain-community

# For the LangGraph examples
uv pip install "tenuo[langgraph]"

# For the MCP examples
uv pip install "tenuo[langgraph,mcp]"

# Set API key
export OPENAI_API_KEY="sk-..."

# Run examples
python create_agent_middleware.py # LangChain 1.x create_agent + TenuoMiddleware (no API key)
python simple.py              # Basic LangChain protection
python integration.py         # Advanced callback patterns
python protect_tools.py       # Securing third-party tools
python mcp_integration.py     # LangChain + MCP + Tenuo
python langgraph_protected.py # State-aware agents
```

## Examples

### [create_agent_middleware.py](create_agent_middleware.py) - LangChain 1.x Quickstart

The shortest current-generation agent: `create_agent()` with `TenuoMiddleware`. Requires `langchain>=1.0`; uses a scripted fake model, so no API key or network is needed. Shows:
- **The `warrant` state field**: the agent's `state_schema` adds `warrant`, and each `agent.invoke({...})` passes the warrant alongside `messages`. The middleware reads it on every model and tool call.
- **Key registration**: the holder key is registered with `KeyRegistry.get_instance().register("support-agent", key)` and selected with `TenuoMiddleware(key_id="support-agent")`, so no environment variables are required.
- **`trusted_roots`**: `TenuoMiddleware(trusted_roots=[issuer_key.public_key])` only accepts warrants issued by that key. Always set it in production.
- An authorized `search` call running, and `delete_record` (not in the warrant) denied without its body executing.

**Start here** for LangChain 1.x agents; the examples below use the older callback and `AgentExecutor`-era APIs.

### [simple.py](simple.py) - Basic Protection

Minimal example of protecting LangChain tools. Shows:
- Tool wrapping with `@guard`
- Warrant creation for LangChain agents
- Running agents with authorization
- Basic error handling

**Use when**: you are on the older `@guard` / callback-based APIs.

### [integration.py](integration.py) - Advanced Callbacks

Advanced integration with LangChain's callback system. Shows:
- Warrant context propagation via callbacks
- Custom callback handlers
- Chain-level authorization
- Multi-step workflow protection

**Use when**: Building complex chains with authorization at each step.

### [protect_tools.py](protect_tools.py) - Third-Party Tools

Securing tools you don't control. Shows:
- Wrapping `langchain_community` tools
- Applying constraints to external tools
- Handling tool signature mismatches
- Runtime constraint extraction

**Use when**: Integrating tools from `langchain_community` or other libraries.

### [mcp_integration.py](mcp_integration.py) - LangChain + MCP

Complete integration of LangChain, MCP, and Tenuo. Shows:
- MCP tool server setup
- Constraint extraction from MCP calls
- End-to-end authorization flow
- Error handling across layers

**Use when**: Building LangChain agents that call MCP servers.

### [langgraph_protected.py](langgraph_protected.py) - State-Aware Agents

Advanced LangGraph integration with checkpointing. Shows:
- Warrant serialization in state (base64 tokens, not objects)
- Key binding at runtime (`from tenuo.keys import KeyRegistry`)
- `from tenuo.langgraph import TenuoToolNode` for secure tool execution
- State transition authorization
- Memory persistence with `MemorySaver`

**Use when**: Building stateful agents with LangGraph.

### [langgraph_mcp_integration.py](langgraph_mcp_integration.py) - LangGraph + MCP

LangGraph agents calling MCP servers. Shows:
- LangGraph + MCP + Tenuo stack
- Graph node authorization
- MCP tool integration
- State management with MCP calls

**Use when**: Building LangGraph agents with MCP backend.

## Key Patterns

| Pattern | Example | Use Case |
|---------|---------|----------|
| **Tool wrapping** | `@guard(tool="...")` | Protecting individual tools |
| **Context propagation** | `with warrant_scope(w), key_scope(k):` or `with warrant.bind(key):` | Thread-safe warrant passing |
| **Third-party tools** | `guard([external_tool], bound)` | Securing tools you don't control |
| **State serialization** | Store warrant tokens, not objects | LangGraph checkpointing |

Note: `warrant_scope(warrant)` alone is not enough for Proof-of-Possession; pair it with `key_scope(key)`, or use `with bound:` where `bound = warrant.bind(key)`.

## Learn More

- [Tenuo Documentation](https://tenuo.ai)
- [LangChain Docs](https://python.langchain.com/)
- [LangGraph Docs](https://langchain-ai.github.io/langgraph/)
- [Main Examples README](../README.md)
