# Integration Compatibility Matrix

**Last Updated**: 2026-09-02

Tracks compatibility between Tenuo and upstream integration libraries.

## Supported Versions

| Integration | Minimum (pyproject) | Recommended | Latest Tested | Status | Notes |
|-------------|---------------------|-------------|---------------|--------|-------|
| **OpenAI** | 1.0.0 | 2.x / 3.x | 3.7.0 | Stable | Agents SDK (`openai-agents`) tested at 0.22.0. CrewAI still requires `openai<3`. |
| **OpenAI Agents** | 0.1 (via openai extra) | latest | 0.22.0 | Stable | Guardrail conversion covered by smoke + adapter tests. |
| **CrewAI** | 1.5.0 | 1.x latest | 1.15.18 | Stable | `GuardedCrew` needs the `crewai.hooks` API (1.5.0+). Pins `openai<3` and `mcp~=1.28` — do not co-install with FastMCP 4 / OpenAI 3 in one env. |
| **AutoGen** | 0.7.0 | 0.7+ latest | 0.7.5 | Stable | Use `autogen-agentchat` / `autogen-ext` (not stale `0.0.x` squat packages). |
| **LangChain** | 0.2.0 | 1.x latest | 1.3.18 / core 1.6.1 | Stable | |
| **LangGraph** | 0.2.0 | 1.x latest | 1.2.11 | Stable | Requires `langchain-core>=0.2.27`. |
| **MCP** | 1.9.4 | 1.x or 2.x | 1.28.1 and 2.1.1 | Stable | Python `tenuo.mcp` supports MCP SDK 1.9.4+ and 2.x (streamable-HTTP transport shape settled in 1.9.4). |
| **FastMCP** | 3.2.1 | 3.x or 4.x | 3.4.7 and 4.0.1 | Stable | FastMCP 4 requires MCP SDK 2.x. Denials are a real `ToolResult` subclass (`isError=True` on the wire) on every line. |
| **Google ADK** | 0.1.0 | latest | 2.8.0 | Stable | GuardBuilder / before_tool covered in CI. |
| **Temporal** | 1.23.0 | 1.x latest | 1.32.0 | Stable | `SimplePlugin` required for `TenuoTemporalPlugin`; replay + live jobs in matrix. |
| **FastAPI** | 0.100.0 | latest | 0.141.1 | Stable | Works with Starlette 1.6.0. |
| **Starlette** | (via fastapi/a2a) | latest | 1.6.0 | Stable | Pulled by FastAPI / A2A. |

> **Version Philosophy**: Tenuo uses **permissive constraints** in `pyproject.toml` to maximize compatibility. We **warn at runtime** (not fail) if you have a version with known issues. This lets you try Tenuo without upgrading your entire stack.
>
> **Runtime Warnings**: If you import a Tenuo integration with a version that has known issues, you'll see a warning like:
> ```
> Tenuo compatibility notice: openai==1.2.0
>   Issue: OpenAI 1.0-1.5 may have httpx compatibility issues
>   Recommendation: Upgrade to openai>=1.6 if you encounter this issue
> ```

### Status Legend
- **Stable**: Production-ready, actively tested
- **Beta**: Works but may have rough edges
- **In Development**: Not yet released
- **Deprecated**: No longer supported

---

## Known Issues

### OpenAI
**Current Status**: Stable (1.x minimum, 2.x/3.x latest)

**Version Notes**:
- OpenAI Python 3.x is supported by `tenuo.openai` and the Agents SDK guardrails.
- CrewAI 1.15.x still requires `openai>=2.30,<3`, so a single environment cannot pin both CrewAI-latest and OpenAI 3.x.

### CrewAI
**Current Status**: Stable

**Version Notes**:
- **< 1.5.0**: No `crewai.hooks` package, so `GuardedCrew` / `CrewAIGuard.register()` raise `ImportError`. The extra now floors at 1.5.
- **1.0.x**: Requires explicit `backstory` for Agent and `expected_output` for Task. Tenuo warns at runtime.
- **1.15.x**: Depends on `mcp~=1.28` and `openai<3`. FastMCP 4 / MCP 2.x must be tested in a separate environment (CI `mcp-smoke` job).

### AutoGen
**Current Status**: Stable

**Version Notes**:
- Install `autogen-agentchat>=0.7` and `autogen-ext[openai]>=0.7`. Avoid resolving the unrelated `0.0.x` packages on PyPI.

### LangChain / LangGraph
**Current Status**: Stable on 0.2+ and 1.x

**Version Notes**:
- **langchain-core 0.2.0-0.2.26**: Incompatible with `langgraph>=0.2` (runtime warning).
- LangChain / LangGraph 1.x validated locally on 2026-09-02.

### MCP / FastMCP
**Current Status**: Stable on MCP 1.x+2.x and FastMCP 3.x+4.x

**Version Notes**:
- MCP SDK < 1.9.4: `mcp.client.streamable_http` is missing or yields two values instead of the `(read, write, get_session_id)` triple `tenuo.mcp` unpacks, and `CallToolRequestParams.meta` is absent on early 1.x. The extras now floor at 1.9.4.
- FastMCP 3.x historically paired with MCP SDK 1.x; FastMCP 4.x requires MCP SDK 2.x.
- Middleware denials are a `ToolResult` subclass on every line: FastMCP 4 only normalizes `ToolResult` returns, `ToolResult.is_error` exists from FastMCP 3.4 onward, and FastMCP's own caching / response-limiting middleware read `.content` / `.structured_content` directly.
- FastMCP 4 stamps only `_meta.fastmcp.version` on the middleware params for version-pinned calls; the `tenuo` block is merged in from the request context.

### Google ADK
**Current Status**: Stable (latest 2.8.0)

**Version Notes**:
- Minimum extra is `google-adk>=0.1`. Latest 2.x validated with GuardBuilder / before_tool tests.

### Temporal
**Current Status**: Stable

**Version Notes**:
- **1.23.0**: Minimum for `TenuoTemporalPlugin` (`SimplePlugin`).
- Replay safety and live Temporal jobs run in the weekly compatibility matrix.

### FastAPI
**Current Status**: Stable

**Version Notes**:
- Works with current FastAPI / Starlette 1.x line. Configure trusted issuers via `configure_tenuo` or global `tenuo.configure(trusted_roots=...)`.

---

## Version Testing Status

Last local probe: 2026-09-02 (adapter suites + expanded smoke tests)

| Integration | Minimum Version | Latest Version | Nightly/Pre-release |
|-------------|----------------|----------------|---------------------|
| OpenAI | Pass (1.6.0 floor) | Pass (3.7.0) | Not tested |
| OpenAI Agents | — | Pass (0.22.0) | Not tested |
| CrewAI | Pass (1.5.0) | Pass (1.15.18) | Not tested |
| AutoGen | Pass (0.7.0) | Pass (0.7.5) | Not tested |
| LangChain | Pass (0.2.x) | Pass (1.3.18) | Not tested |
| LangGraph | Pass (0.2.0) | Pass (1.2.11) | Not tested |
| MCP | Pass (1.9.4) | Pass (2.1.1) | Not tested |
| FastMCP | Pass (3.2.1) | Pass (3.4.7 / 4.0.1) | Not tested |
| Google ADK | Pass (0.1+) | Pass (2.8.0) | Not tested |
| Temporal | Pass (1.23.0) | Pass (1.32.0) | Not tested |
| FastAPI | Pass (0.100+) | Pass (0.141.1) | Not tested |

**Testing Cadence**:
- Main CI: installs OpenAI, Agents SDK, AutoGen, Google ADK, LangChain/LangGraph, FastAPI, CrewAI, MCP, Temporal (where Python allows)
- MCP / FastMCP: dedicated dual-line `mcp-smoke` CI jobs (latest `FastMCP 3` + MCP 1.x, `FastMCP 4` + MCP 2.x) gated by `scripts/check_installed_majors.py` so CrewAI's MCP 1.x pin cannot hide regressions; the 3.2.1 floor runs in the weekly matrix
- Weekly compatibility matrix: minimum + latest per integration (including FastAPI, Google ADK, MCP, FastMCP, Temporal)

---

## Deprecation Timeline

### Scheduled Deprecations
None currently scheduled.

### Watching
- **CrewAI**: OpenAI 3 / MCP 2 adoption path
- **OpenAI**: 3.x ecosystem adoption alongside Agents SDK
- **LangChain/LangGraph**: joint 1.x compatibility surface
- **FastMCP**: 4.x + MCP SDK 2.x as the default server stack
- **Google ADK**: 2.x plugin / callback API stability
- **Temporal**: `SimplePlugin` / sandbox restriction changes

---

## Reporting Compatibility Issues

If you encounter compatibility issues:

1. **Check this matrix** for known issues
2. **Search existing issues**: [Integration label](https://github.com/tenuo-ai/tenuo/labels/integration)
3. **Open new issue** with:
   - Integration name and version
   - Tenuo version
   - Python version
   - Minimal reproduction case
   - Error message/traceback

**Issue Template**: Use the "Integration Compatibility" template when creating issues.

---

## Changelog References

Quick links to upstream changelogs:

- [OpenAI Python Changelog](https://github.com/openai/openai-python/releases)
- [OpenAI Agents SDK](https://github.com/openai/openai-agents-python/releases)
- [CrewAI Releases](https://github.com/joaomdmoura/crewAI/releases)
- [AutoGen Changelog](https://github.com/microsoft/autogen/releases)
- [LangChain Changelog](https://python.langchain.com/changelog)
- [LangGraph Releases](https://github.com/langchain-ai/langgraph/releases)
- [MCP Releases](https://github.com/modelcontextprotocol/python-sdk/releases)
- [FastMCP Releases](https://github.com/PrefectHQ/fastmcp/releases)
- [Google ADK Releases](https://github.com/google/adk-python/releases)
- [Temporal Python SDK Releases](https://github.com/temporalio/sdk-python/releases)
- [FastAPI Releases](https://github.com/fastapi/fastapi/releases)

---

## Maintenance Policy

Tenuo maintains compatibility with:
- **Latest major version** + previous major version
- **Latest 2 minor versions** within supported major
- **Minimum version** as declared in `pyproject.toml`

**Example**: If latest is 2.5.0, we support:
- 2.5.x (latest)
- 2.4.x (previous minor)
- 1.x.x (previous major, best-effort)
- Minimum declared version (always tested)

---

## Contributing

Help us maintain compatibility:

1. **Report issues early**: Beta test new releases
2. **Add smoke tests** in `tenuo-python/tests/e2e/test_smoke.py` for new public APIs
3. **Update this matrix** when validating a new upstream major
