# Tenuo × LangChain Examples

Examples demonstrating Tenuo integration with LangChain and LangGraph.

## Quick Start

```bash
# Install dependencies
uv pip install tenuo langchain langchain-openai langchain-community langgraph

# Set API key
export OPENAI_API_KEY="sk-..."

# Run examples
python simple.py              # Basic LangChain protection
python integration.py         # Advanced callback patterns
python protect_tools.py       # Securing third-party tools
python mcp_integration.py     # LangChain + MCP + Tenuo
python langgraph_protected.py # State-aware agents
```

## Examples

### [simple.py](simple.py) - Basic Protection

Minimal example of protecting LangChain tools. Shows:
- Tool wrapping with `@guard`
- Warrant creation for LangChain agents
- Running agents with authorization
- Basic error handling

**Start here** for LangChain integration.

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
- Key binding at runtime (`KeyRegistry`)
- `TenuoToolNode` for secure tool execution
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
| **Tool wrapping** | `@guard(warrant, tool="...")` | Protecting individual tools |
| **Context propagation** | `warrant_scope(warrant)` | Thread-safe warrant passing |
| **Third-party tools** | `guard(external_tool, ...)` | Securing tools you don't control |
| **State serialization** | Store warrant tokens, not objects | LangGraph checkpointing |

## Learn More

- [Tenuo Documentation](https://tenuo.ai)
- [LangChain Docs](https://python.langchain.com/)
- [LangGraph Docs](https://langchain-ai.github.io/langgraph/)
- [Main Examples README](../README.md)
