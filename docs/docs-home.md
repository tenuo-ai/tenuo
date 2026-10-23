---
title: Documentation
description: Learn Tenuo, add it to your agent framework, and ship it to production.
permalink: /docs/
---

# Tenuo documentation

Tenuo checks every tool call your agent makes against a signed warrant. The warrant says which tools the agent may call, which argument values are allowed, and when that permission expires. When work is handed to another agent, the warrant can only get narrower.

These docs show you how to add that check, where to run it, and how to ship it.

## New to Tenuo

1. **[Why Tenuo](/concepts)** explains the gap between what an agent's identity allows and what its task needs.
2. **[Quickstart](/quickstart/)** protects one Python function. You'll see an allowed call and a blocked call in about five minutes.
3. **[Hands-on lab](/lab/)** is a 90-minute challenge: six agents book a trip, one of them is compromised, and you scope each one so the rogue can't do damage.

## Add Tenuo to your stack

[Integrations](/integrations/) lists every supported framework with its install line and guide. The most used:

- [OpenAI](/openai) · [LangChain](/langchain) · [LangGraph](/langgraph) · [CrewAI](/crewai) · [Google ADK](/google-adk)
- [MCP](/mcp) for tool servers, [A2A](/a2a) for agents that hand work to each other
- [Temporal](/temporal) for durable workflows

## Ship it

- **[Choose where the check runs](/enforcement):** in the agent's process, in a sidecar, or at a gateway. Each choice survives a different kind of compromise.
- **[Going to production](/production-guide):** leave `dev_mode`, manage keys, and roll out in audit mode first.
- **[Kubernetes](/kubernetes)**, **[Envoy](/quickstart/envoy/)** and **[Istio](/quickstart/istio/)** deployment guides.

## Look something up

- [Constraints](/constraints) for limiting argument values: paths, URLs, ranges, shell commands
- [Debug a denial](/debugging) when a call you expected to pass is blocked
- [Python API reference](/api-reference)
- [Security model](/security) for what Tenuo protects against, and what it doesn't
- [Protocol specification](/spec/) for the warrant format and verification rules

## Tenuo Cloud

The open-source SDKs mint and verify warrants on their own. [Tenuo Cloud](https://cloud.tenuo.ai) adds a managed control plane with warrant issuance, revocation and observability across your agents.
