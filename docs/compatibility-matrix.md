# Integration Compatibility Matrix

**Last Updated**: 2026-02-03

Tracks compatibility between Tenuo and upstream integration libraries.

## Supported Versions

| Integration | Minimum (pyproject) | Recommended | Latest Tested | Status | Notes |
|-------------|---------------------|-------------|---------------|--------|-------|
| **OpenAI** | 1.0.0 | 1.50+ | 1.52.0 | ✅ Stable | Full feature support |
| **CrewAI** | 1.0.0 | 1.9+ | 1.9.4 | ✅ Stable | All tiers supported |
| **AutoGen** | 0.7.0 | 0.9+ | 0.9.2 | ✅ Stable | AgentChat integration |
| **LangChain** | 0.2.0 | 0.3+ | 0.3.5 | ✅ Stable | LangChain Core |
| **LangGraph** | 0.2.0 | 0.2+ | 0.2.8 | ✅ Stable | StateGraph support |
| **MCP** | 1.0.0 | 1.1+ | 1.1.3 | ✅ Stable | Model Context Protocol |
| **Google ADK** | 0.1.0 | 0.1+ | 0.1.2 | ⚠️ Beta | Early access |

> **Version Philosophy**: Tenuo uses **permissive constraints** in `pyproject.toml` to maximize compatibility. We **warn at runtime** (not fail) if you have a version with known issues. This lets you try Tenuo without upgrading your entire stack.
>
> **Runtime Warnings**: If you import a Tenuo integration with a version that has known issues, you'll see a warning like:
> ```
> Tenuo compatibility notice: openai==1.2.0
>   Issue: OpenAI 1.0-1.5 may have httpx compatibility issues
>   Recommendation: Upgrade to openai>=1.6 if you encounter this issue
> ```

### Status Legend
- ✅ **Stable**: Production-ready, actively tested
- ⚠️ **Beta**: Works but may have rough edges
- 🚧 **In Development**: Not yet released
- ❌ **Deprecated**: No longer supported

---

## Known Issues

### OpenAI
**Current Status**: ✅ No known issues (1.6+)

**Version Notes**:
- **1.0-1.5**: May have httpx compatibility issues (`proxies` argument conflict). Tenuo will warn at runtime but allow installation.
- **1.6+**: Fully compatible, no known issues.

**Recent Changes**:
- 1.50.0: Added streaming support for tool calls (✅ Compatible)
- 1.40.0: Response format changes (✅ Compatible)
- 1.6.0: Fixed httpx compatibility

**Next Breaking Change**: OpenAI 2.0 (TBD)
- Expected changes: Client constructor signature
- **Tracking**: [Issue TBD](https://github.com/tenuo-ai/tenuo/labels/openai)

### CrewAI
**Current Status**: ✅ No known issues (1.1+)

**Version Notes**:
- **1.0.x**: Requires explicit `backstory` for Agent and `expected_output` for Task. Tenuo's wrapper code works, but you must provide these fields. Tenuo will warn at runtime.
- **1.1+**: Fully compatible, no known issues.

**Recent Changes**:
- 1.9.0: Added hierarchical process support (✅ Compatible)
- 1.5.0: Tool signature changes (✅ Backwards compatible)
- 1.1.0: Made backstory/expected_output have defaults

**Next Breaking Change**: CrewAI 2.0 (Q2 2026 estimated)
- Expected changes: Async tool support
- **Impact**: Medium - will require adapter pattern updates
- **Tracking**: [Issue TBD](https://github.com/tenuo-ai/tenuo/labels/crewai)

### AutoGen
**Current Status**: ✅ No known issues

**Recent Changes**:
- 0.9.0: New AgentChat API (✅ Compatible)
- 0.7.0: Initial release (✅ Compatible)

**Next Breaking Change**: AutoGen 1.0 (TBD)
- Expected changes: API stabilization
- **Impact**: Low - mostly additive changes expected

### LangChain
**Current Status**: ✅ No known issues

**Version Notes**:
- **0.2.0-0.2.26**: Works standalone, but incompatible with langgraph>=0.2. Tenuo will warn if you use langgraph.
- **0.2.27+**: Fully compatible with all Tenuo integrations including langgraph.

**Recent Changes**:
- 0.3.0: Pydantic v2 migration (✅ Compatible)
- 0.2.27: Compatible with langgraph 0.2.0
- 0.2.0: Core extraction

### LangGraph
**Current Status**: ✅ No known issues

**Version Notes**:
- **0.2.0+**: Requires `langchain-core>=0.2.27`. Tenuo's `[langgraph]` extra handles this automatically.
- **0.0.x/0.1.x**: Not supported (requires langchain-core<0.2, which conflicts with our langchain integration).

**Recent Changes**:
- 0.2.0: Updated to support langchain-core>=0.2
- 0.1.0: Initial stable release (incompatible with our langchain-core requirement)

---

## Version Testing Status

Last tested: 2026-02-03

| Integration | Minimum Version | Latest Version | Nightly/Pre-release |
|-------------|----------------|----------------|---------------------|
| OpenAI | ✅ Pass | ✅ Pass | ⚠️ Warnings |
| CrewAI | ✅ Pass | ✅ Pass | 🔄 Not tested |
| AutoGen | ✅ Pass | ✅ Pass | ✅ Pass |
| LangChain | ✅ Pass | ✅ Pass | ✅ Pass |
| LangGraph | ✅ Pass | ✅ Pass | ⚠️ Minor issues |

**Testing Cadence**:
- Minimum versions: Weekly
- Latest versions: Weekly
- Pre-release: Manual (on major releases)

---

## Deprecation Timeline

### Scheduled Deprecations
None currently scheduled.

### Watching
- **CrewAI 1.x**: Monitoring for 2.0 announcement
- **OpenAI 1.x**: Monitoring for 2.0 announcement

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
- [CrewAI Releases](https://github.com/joaomdmoura/crewAI/releases)
- [AutoGen Changelog](https://github.com/microsoft/autogen/releases)
- [LangChain Changelog](https://python.langchain.com/changelog)
- [LangGraph Releases](https://github.com/langchain-ai/langgraph/releases)
- [MCP Releases](https://github.com/modelcontextprotocol/python-sdk/releases)

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
2. **Share workarounds**: Document temporary fixes
3. **Submit PRs**: Fix compatibility issues
4. **Join discussions**: [GitHub Discussions](https://github.com/tenuo-ai/tenuo/discussions)

---

*This matrix is automatically updated weekly. Last automation run: 2026-02-03*
