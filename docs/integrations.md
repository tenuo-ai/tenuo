---
title: Integrations
description: Add Tenuo to an agent framework, protocol, workflow runtime or web framework, or enforce at a gateway.
permalink: /integrations/
---

# Integrations

Pick the guide for the framework your agent already uses. Each one shows where the warrant is checked and walks through a full working example.

If you haven't run Tenuo yet, start with the [Quickstart](/quickstart/). It uses plain Python functions, so the ideas carry over to every integration below.

## Agent frameworks

| Framework | Install | Start with | Guide |
|---|---|---|---|
| OpenAI SDK | `uv pip install "tenuo[openai]"` | `from tenuo.openai import guard` | [OpenAI](/openai) |
| LangChain | `uv pip install "tenuo[langchain]"` | `from tenuo.langchain import auto_protect` | [LangChain](/langchain) |
| LangGraph | `uv pip install "tenuo[langgraph]"` | `from tenuo.langgraph import guard_node` | [LangGraph](/langgraph) |
| CrewAI | `uv pip install "tenuo[crewai]"` | `from tenuo.crewai import GuardBuilder` | [CrewAI](/crewai) |
| Google ADK | `uv pip install "tenuo[google_adk]"` | `from tenuo.google_adk import TenuoGuard` | [Google ADK](/google-adk) |
| AutoGen AgentChat | `uv pip install "tenuo[autogen]"` | `from tenuo.autogen import guard_tool` | [AutoGen](/autogen) |
| Hermes Agent | `hermes plugins install hermes-tenuo` | Configured in `~/.hermes/config.yaml` | [Hermes Agent](/hermes) |

## Protocols

| Protocol | Install | Start with | Guide |
|---|---|---|---|
| MCP | `uv pip install "tenuo[mcp]"` | `from tenuo.mcp import SecureMCPClient` | [MCP](/mcp) |
| A2A | `uv pip install "tenuo[a2a]"` | `from tenuo.a2a import A2AServerBuilder` | [A2A](/a2a) |

If your agents hand work to each other across processes, add A2A alongside your framework integration. The receiving agent then checks the narrower warrant it was given.

## Workflow runtimes

| Runtime | Install | Start with | Guide |
|---|---|---|---|
| Temporal | `uv pip install "tenuo[temporal]"` | `from tenuo.temporal import TenuoTemporalPlugin` | [Temporal quickstart](/temporal-quickstart), then [Temporal](/temporal) |
| Temporal Nexus | `uv pip install "tenuo[temporal]"` | `from tenuo.templates import TemporalNexusOperation` | [Temporal Nexus](/temporal-nexus) |

## Web frameworks

| Framework | Install | Start with | Guide |
|---|---|---|---|
| FastAPI | `uv pip install "tenuo[fastapi]"` | `from tenuo.fastapi import SecureAPIRouter` | [FastAPI](/fastapi) |

## Gateways and infrastructure

Run the check outside the agent's process, so that it still holds if the agent is compromised. [Choose where the check runs](/enforcement) explains the trade-offs.

| Where | Guide |
|---|---|
| Envoy `ext_authz` | [Envoy gateway](/quickstart/envoy/) |
| Istio mesh | [Istio mesh](/quickstart/istio/) |
| Kubernetes sidecar | [Kubernetes](/kubernetes) |

## TypeScript

The TypeScript SDK is in beta and requires Node 20 or newer.

| Package | Install | Docs |
|---|---|---|
| `@tenuo/core` | `npm i @tenuo/core@beta` | [TypeScript SDK README](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts) |
| `@tenuo/mcp` | `npm i @tenuo/mcp@beta @modelcontextprotocol/server` | [TypeScript SDK README](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-ts) |

## Something else

If your framework isn't listed, call the core API directly. Wrap a tool with `@guard`, or verify a warrant yourself with `Authorizer`. See the [Python API reference](/api-reference).
