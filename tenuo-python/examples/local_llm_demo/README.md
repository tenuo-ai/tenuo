# Local LLM Prompt Injection Demo

> **Capability-Based Security vs Prompt Injection**

This demo shows how **Tenuo's Capability-Based Authorization** prevents a compromised LLM from performing unauthorized actions, even when it has been successfully "jailbroken" by prompt injection.

## Quick Start

### Option 1: Simulation Mode (no LLM required)

```bash
python demo.py --simulate
```

This directly tests Tenuo's blocking without needing an LLM. Great for quickly seeing what Tenuo blocks.

### Option 2: Full Demo with Local LLM

1. Start **LM Studio** and load a model (e.g., `qwen2.5-7b-instruct`)
2. Enable the Local Server on port 1234
3. Run: `python demo.py`

## What the Demo Shows

### The Scenario

1. A **Research Agent** is given limited permissions via a Tenuo warrant
2. It searches for papers (search results contain hidden malicious instructions)
3. The LLM may try to follow these malicious instructions
4. **Tenuo blocks all unauthorized actions**

### Attack Types Demonstrated

| Attack | What it Tries | Tenuo Response |
|--------|--------------|----------------|
| Data Exfiltration | Send data to `evil.example.com` via `http_request` | **BLOCKED** - Tool not in warrant |
| Path Traversal | Read `/etc/passwd` or SSH keys | **BLOCKED** - Path outside allowed scope |
| Privilege Escalation | Delegate with `path=/*` (all files) | **BLOCKED** - Cannot grant more than you have |

### Key Security Concepts

- **Principle of Least Authority**: Agents only have access to explicitly granted capabilities
- **Constraint Enforcement**: Even allowed tools must satisfy argument constraints
- **Monotonic Attenuation**: Child warrants can only have fewer permissions, never more

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Control Plane                              │
│                  (Issues root warrant)                          │
└─────────────────────────┬───────────────────────────────────────┘
                          │ Warrant
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Research Agent                              │
│  Capabilities:                                                  │
│    ✓ web_search (domain: arxiv.org)                            │
│    ✓ read_file (path: /tmp/research/*)                         │
│    ✓ write_file (path: /tmp/research/*)                        │
│    ✓ delegate                                                   │
│    ✗ http_request (not granted)                                │
└─────────────────────────┬───────────────────────────────────────┘
                          │ Child Warrant (attenuated)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Summary Agent                               │
│  Capabilities (subset of parent):                               │
│    ✓ read_file (path: /tmp/research/*)                         │
│    ✗ Cannot exceed parent's permissions                         │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Edit `config.py` to:

- Set `LM_STUDIO_MODEL_ID` to target a specific model
- Change `LM_STUDIO_URL` if not using default port
- Enable/disable `USE_MOCK_SEARCH` (mock injects attack payloads)
- Set `TAVILY_API_KEY` for real web search

## Files Overview

| File | Purpose |
|------|---------|
| `demo.py` | Main entry point |
| `agents.py` | Research and Summary agent logic |
| `protected_tools.py` | Tenuo authorization wrapper |
| `tools.py` | Tool implementations |
| `payloads.py` | Malicious payloads for demo |
| `prompts.py` | LLM system prompts |
| `display.py` | Rich console output |
| `config.py` | Configuration settings |
