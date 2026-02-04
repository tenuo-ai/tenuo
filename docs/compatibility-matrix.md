# Integration Compatibility Matrix

**Last Updated**: 2026-02-03

Tracks compatibility between Tenuo and upstream integration libraries.

## Supported Versions

| Integration | Minimum | Recommended | Latest Tested | Status | Notes |
|-------------|---------|-------------|---------------|--------|-------|
| **OpenAI** | 1.6.0 | 1.50+ | 1.52.0 | ✅ Stable | Full feature support |
| **CrewAI** | 1.1.0 | 1.9+ | 1.9.4 | ✅ Stable | All tiers supported |
| **AutoGen** | 0.7.0 | 0.9+ | 0.9.2 | ✅ Stable | AgentChat integration |
| **LangChain** | 0.2.0 | 0.3+ | 0.3.5 | ✅ Stable | LangChain Core |
| **LangGraph** | 0.2.0 | 0.2+ | 0.2.8 | ✅ Stable | StateGraph support |
| **MCP** | 1.0.0 | 1.1+ | 1.1.3 | ✅ Stable | Model Context Protocol |
| **Google ADK** | 0.1.0 | 0.1+ | 0.1.2 | ⚠️ Beta | Early access |

> **Note on Minimum Versions**: These are the oldest versions tested in CI. Earlier versions may have dependency conflicts or missing required features. See [Known Issues](#known-issues) for details.

### Status Legend
- ✅ **Stable**: Production-ready, actively tested
- ⚠️ **Beta**: Works but may have rough edges
- 🚧 **In Development**: Not yet released
- ❌ **Deprecated**: No longer supported

---

## Known Issues

### OpenAI
**Current Status**: ✅ No known issues

**Minimum Version**: 1.6.0
- Versions 1.0-1.5 have httpx compatibility issues (`proxies` argument conflict)
- The `OpenAI()` client constructor fails with `TypeError: Client.__init__() got an unexpected keyword argument 'proxies'`

**Recent Changes**:
- 1.50.0: Added streaming support for tool calls (✅ Compatible)
- 1.40.0: Response format changes (✅ Compatible)
- 1.6.0: Fixed httpx compatibility (✅ Minimum supported)

**Next Breaking Change**: OpenAI 2.0 (TBD)
- Expected changes: Client constructor signature
- **Tracking**: [Issue TBD](https://github.com/tenuo-ai/tenuo/labels/openai)

### CrewAI
**Current Status**: ✅ No known issues

**Minimum Version**: 1.1.0
- Version 1.0 is missing required fields (`backstory` for Agent, `expected_output` for Task)
- Agent/Task creation fails with `ValidationError: Field required`

**Recent Changes**:
- 1.9.0: Added hierarchical process support (✅ Compatible)
- 1.5.0: Tool signature changes (✅ Backwards compatible)
- 1.1.0: Added required fields for Agent/Task (✅ Minimum supported)

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

**Recent Changes**:
- 0.3.0: Pydantic v2 migration (✅ Compatible)
- 0.2.0: Core extraction (✅ Compatible)

### LangGraph
**Current Status**: ✅ No known issues

**Minimum Version**: 0.2.0
- Versions 0.0.x and 0.1.x require `langchain-core<0.2.0`
- Cannot be installed alongside `langchain-core>=0.2` (dependency conflict)

**Recent Changes**:
- 0.2.0: Updated to support langchain-core>=0.2 (✅ Minimum supported)
- 0.1.0: Initial stable release (❌ Incompatible with langchain-core>=0.2)

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
