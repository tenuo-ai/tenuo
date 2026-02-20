# Tenuo MCP Examples

Model Context Protocol (MCP) integration with Tenuo's cryptographic authorization.

## What This Directory Contains

Examples showing how to secure MCP tools with Tenuo warrants across different frameworks and architectures.

**Core Pattern**: MCP tools → Tenuo authorization → Constrained execution

---

## Examples in This Directory

### 1. [`mcp_client_demo.py`](mcp_client_demo.py) - Basic Client Integration

Full integration using `SecureMCPClient` with automatic tool discovery and protection.

**What it shows:**
- Connecting to MCP server via stdio
- Automatic tool discovery and wrapping
- Warrant-scoped execution with `mint()`
- Local vs remote authorization patterns
- Constraint enforcement

**Run:**
```bash
python mcp_client_demo.py
```

**Architecture:**
```
Client (SecureMCPClient) → MCP Server (stdio)
         ↓
    Warrant Check
         ↓
   Tool Execution
```

---

### 2. [`langchain_mcp_demo.py`](langchain_mcp_demo.py) - LangChain Integration

LangChain agents using MCP tools with warrant authorization.

**What it shows:**
- `MCPToolAdapter` converting MCP tools to LangChain `StructuredTool`
- LangChain agent with protected MCP tools
- ReAct agent workflow with constrained tools
- Schema-based constraint extraction
- Attack demonstrations (path traversal, unauthorized access)

**Run:**
```bash
# Install dependencies
uv pip install "tenuo[langchain,mcp]" langchain-openai

# Set API key
export OPENAI_API_KEY=your-key

# Run demo
python langchain_mcp_demo.py
```

**Architecture:**
```
LangChain Agent → MCPToolAdapter → SecureMCPClient → MCP Server
                       ↓
                 Warrant Check
                       ↓
                Tool Execution
```

---

### 3. [`mcp_a2a_delegation.py`](mcp_a2a_delegation.py) - Multi-Agent with A2A

Multi-agent system where agents delegate MCP tool usage through A2A protocol.

**What it shows:**
- A2A agents exposing MCP tools as skills
- Orchestrator → Worker delegation with MCP tools
- Warrant attenuation for MCP tool access
- Multi-hop authorization (Control → Orchestrator → Worker → MCP)
- MCP tools used in distributed agent architecture
- Attack scenarios: warrant theft, privilege escalation

**Run:**
```bash
uv pip install "tenuo[a2a,mcp]"

python mcp_a2a_delegation.py
```

**Architecture:**
```
Control Plane
      ↓
  Orchestrator (A2A Client)
      ↓
Worker Agents (A2A Servers with MCP clients)
      ↓
  MCP Servers
```

---

### 4. [`crewai_mcp_demo.py`](crewai_mcp_demo.py) - CrewAI Integration

CrewAI crew using MCP tools with per-agent warrant scoping.

**What it shows:**
- CrewAI agents with MCP tool access
- Research → Write → Edit workflow using MCP tools
- Per-agent warrant attenuation (least privilege)
- Researcher: read-only MCP tools (web_search, read_file)
- Writer: write-only MCP tools (write_file)
- Editor: read-only MCP tools (read_file, verify)
- Constraint enforcement in crew workflows

**Run:**
```bash
uv pip install "tenuo[mcp]" crewai

python crewai_mcp_demo.py
```

**Architecture:**
```
CrewAI Orchestrator
├─ Researcher → MCP Tools (search, read)
├─ Writer     → MCP Tools (write)
└─ Editor     → MCP Tools (read, verify)
```

---

### 5. [`mcp_integration.py`](mcp_integration.py) - Low-Level Manual Integration

Manual constraint extraction and authorization without high-level wrappers.

**What it shows:**
- Loading MCP configuration from YAML
- Manual constraint extraction with `CompiledMcpConfig`
- Explicit authorization with `Authorizer.check()`
- Proof-of-Possession signature creation
- Direct warrant authorization API

**Run:**
```bash
python mcp_integration.py
```

**Use when:**
- Building custom MCP client wrappers
- Understanding low-level authorization flow
- Debugging constraint extraction issues

---

### 6. [`mcp_server_demo.py`](mcp_server_demo.py) - Test MCP Server

Simple MCP server for testing Tenuo integration.

**What it provides:**
- `read_file` tool with path and max_size constraints
- `list_directory` tool with path constraints
- Stdio transport for local testing

**Run:**
```bash
# Server runs automatically when client connects
# Or run standalone:
python mcp_server_demo.py
```

---

### 7. [`mcp_research_server.py`](mcp_research_server.py) - Research Agent Server

MCP server with web search and file operations for research workflows.

**What it provides:**
- `web_search` tool with domain constraints (uses Tavily API or mock)
- `write_file` tool restricted to `/tmp/research/`
- `read_file` tool restricted to `/tmp/research/`
- Real web search integration (optional)

**Run:**
```bash
# Optional: Set Tavily API key for real search
export TAVILY_API_KEY=your-key

# Server runs automatically when client connects
python mcp_research_server.py
```

---

## Quick Start (5 Minutes)

### 1. Install Dependencies

```bash
uv pip install "tenuo[mcp]"
```

### 2. Run Basic Demo

```bash
python mcp_client_demo.py
```

This connects to the test MCP server, discovers tools, and executes with warrant authorization.

---

## Integration Patterns

### Pattern 1: SecureMCPClient (Recommended)

Built-in client with automatic discovery and protection.

```python
from tenuo.mcp import SecureMCPClient
from tenuo import configure, mint, Capability, Subpath, SigningKey

key = SigningKey.generate()
configure(issuer_key=key)

async with SecureMCPClient("python", ["server.py"], register_config=True) as client:
    async with mint(Capability("read_file", path=Subpath("/data"))):
        result = await client.tools["read_file"](path="/data/file.txt")
```

### Pattern 2: LangChain Integration

Convert MCP tools to LangChain `StructuredTool`.

```python
from tenuo.mcp import SecureMCPClient, MCPToolAdapter
from langchain.agents import AgentExecutor, create_react_agent

async with SecureMCPClient(...) as client:
    # Convert to LangChain tools
    mcp_tools = await client.get_tools()
    langchain_tools = [MCPToolAdapter(tool, client) for tool in mcp_tools]

    # Use in agent
    agent = create_react_agent(llm, langchain_tools, prompt)
    executor = AgentExecutor(agent=agent, tools=langchain_tools)
```

### Pattern 3: A2A Delegation

MCP tools exposed through A2A protocol for multi-agent systems.

```python
from tenuo.a2a import A2AServer
from tenuo.mcp import SecureMCPClient

# Worker agent exposes MCP tools via A2A
server = A2AServer(...)

@server.skill("search_files")
async def search_files(path: str, pattern: str):
    # Use MCP tool internally
    async with mcp_client:
        return await mcp_client.tools["search"](path=path, pattern=pattern)
```

### Pattern 4: CrewAI Workflows

CrewAI agents with MCP tool access.

```python
from crewai import Agent, Task, Crew
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient(...) as client:
    # Create agents with MCP tools
    researcher = Agent(
        role="Researcher",
        tools=[client.tools["web_search"], client.tools["read_file"]],
        ...
    )

    crew = Crew(agents=[researcher, ...])
```

---

## Configuration

### MCP Config File

Define constraint extraction from MCP arguments:

```yaml
# mcp-config.yaml
version: "1"

tools:
  read_file:
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1048576
```

See [`../../examples/mcp-config.yaml`](../../examples/mcp-config.yaml) for comprehensive examples.

---

## When to Use Which Pattern?

| Pattern | Use When | Example |
|---------|----------|---------|
| **SecureMCPClient** | Direct MCP tool usage with automatic protection | Single agent with MCP tools |
| **LangChain + MCP** | LangChain agents need MCP tools | ReAct agent with filesystem access |
| **MCP + A2A** | Multi-agent system with MCP tools | Orchestrator delegates to workers with MCP capabilities |
| **CrewAI + MCP** | Crew workflows need constrained MCP tools | Research crew with web search and file ops |
| **Manual Integration** | Custom authorization logic needed | Specialized constraint extraction |

---

## Framework Integrations

### With LangChain

See [`langchain_mcp_demo.py`](langchain_mcp_demo.py) for complete example:
- MCPToolAdapter for tool conversion
- ReAct agent with MCP tools
- Warrant-scoped execution

### With CrewAI

See [`crewai_mcp_demo.py`](crewai_mcp_demo.py) for complete example:
- Crew workflows with MCP tools
- Per-agent warrant attenuation
- Multi-stage authorization

### With A2A

See [`mcp_a2a_delegation.py`](mcp_a2a_delegation.py) for complete example:
- MCP tools in distributed agents
- Multi-hop warrant chains
- Worker agents with MCP clients

### With Google ADK

See [`../google_adk_a2a_incident/`](../google_adk_a2a_incident/) - ADK agents can use MCP tools through A2A delegation.

---

## Common Issues

### Q: "MCP SDK not installed"

**Fix:**
```bash
uv pip install "tenuo[mcp]"
```

Requires Python 3.10+ (MCP SDK requirement).

### Q: "Tool not found in warrant"

**Problem:** Tool name doesn't match warrant capability name.

**Fix:** Ensure warrant capability name matches MCP tool name:
```python
# MCP tool: "read_file"
warrant = Warrant.mint_builder().capability("read_file", ...).mint(key)
```

### Q: "Constraint violation" but warrant looks correct

**Problem:** Extracted constraint value doesn't satisfy warrant.

**Debug:** Check MCP config extraction:
```python
result = compiled.extract_constraints("read_file", arguments)
print(result.constraints)  # Shows extracted values
```

### Q: "Connection failed" to MCP server

**Problem:** Server script path incorrect or server crashed.

**Fix:**
- Check server script exists: `ls mcp_server_demo.py`
- Test server standalone: `python mcp_server_demo.py`
- Check server logs for errors

### Q: LangChain agent ignores constraints

**Problem:** Using raw MCP tools instead of wrapped tools.

**Fix:** Use `MCPToolAdapter`:
```python
langchain_tools = [MCPToolAdapter(tool, client) for tool in mcp_tools]
```

---

## Example Progression

Start simple, build up complexity:

| Example | Complexity | Concepts |
|---------|-----------|----------|
| **mcp_client_demo.py** | ⭐ Basic | SecureMCPClient, automatic protection |
| **langchain_mcp_demo.py** | ⭐⭐ Intermediate | Framework integration, ReAct agent |
| **crewai_mcp_demo.py** | ⭐⭐ Intermediate | Crew workflows, per-agent warrants |
| **mcp_a2a_delegation.py** | ⭐⭐⭐ Advanced | Multi-agent, A2A protocol, warrant chains |
| **mcp_integration.py** | ⭐⭐⭐ Advanced | Low-level API, manual extraction |

**Recommended learning path:**
1. Start with `mcp_client_demo.py` to understand basic MCP + Tenuo
2. Try `langchain_mcp_demo.py` to see framework integration
3. Explore `crewai_mcp_demo.py` for crew workflows
4. Study `mcp_a2a_delegation.py` for distributed systems

---

## Documentation

- **[MCP Integration Guide](../../../docs/mcp.md)** - Complete API reference
- **[Constraints Reference](../../../docs/constraints.md)** - Available constraint types
- **[Security Model](../../../docs/security.md)** - Threat model and mitigations
- **[A2A Integration](../a2a/)** - Agent-to-agent protocol examples

---

## Need Help?

- **Issues**: [GitHub Issues](https://github.com/tenuo-ai/tenuo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/tenuo-ai/tenuo/discussions)
- **MCP Docs**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
