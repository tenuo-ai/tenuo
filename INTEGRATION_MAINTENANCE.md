# Integration Maintenance System

**For Tenuo Contributors & Maintainers**

Automated system to track and respond to API changes in upstream integration libraries (OpenAI, CrewAI, AutoGen, LangChain, LangGraph).

## Quick Start

```bash
# Run smoke tests
pytest tenuo-python/tests/integration/test_smoke.py -v

# Check for recent upstream changes
python scripts/check_upstream_changes.py --days 7
```

## Automated Monitoring

### 1. Dependabot (`.github/dependabot.yml`)
- Weekly dependency update PRs (Monday 9am UTC)
- Updates grouped by integration
- Covers Python, Rust, npm, and GitHub Actions

### 2. Compatibility Matrix (`.github/workflows/integration-compatibility-matrix.yml`)
- Tests minimum and latest versions weekly
- Runs on integration file changes
- Auto-creates issues on failures

### 3. Release Monitor (`.github/workflows/monitor-upstream-releases.yml`)
- Daily checks for new releases (8am UTC)
- Searches for breaking change keywords
- Auto-creates issues with changelogs

### 4. Smoke Tests (`tenuo-python/tests/integration/test_smoke.py`)
- Verifies API contracts haven't changed
- Tests imports, class existence, basic methods
- Runs in CI matrix across Python versions

## Weekly Routine

**Monday Morning** (30-60 minutes):

```bash
# 1. Check Dependabot PRs
gh pr list --label dependencies

# 2. Review CI results
gh run list --workflow=integration-compatibility-matrix.yml --limit=1

# 3. Check auto-created issues
gh issue list --label release-alert

# 4. Manual verification
python scripts/check_upstream_changes.py --days 7
```

## Responding to Breaking Changes

1. Review upstream changelog in detail
2. Run smoke tests: `pytest tests/integration/test_smoke.py -k <integration>`
3. Update integration code if needed
4. Update `docs/compatibility-matrix.md`
5. Test examples to verify
6. Update version constraints in `pyproject.toml` if needed

### Escalation Policy

| Priority | Definition | Response Time |
|----------|------------|---------------|
| **P0** | Blocks users, no workaround | Fix within 48 hours |
| **P1** | Workaround exists | Fix within 1 week |
| **P2** | Minor impact | Fix in next release |

## Support Policy

Tenuo maintains compatibility with:
- Latest major version + previous major
- Latest 2 minor versions within major
- Minimum version declared in `pyproject.toml`

**Example**: If latest is 2.5.0, we support:
- 2.5.x (latest minor)
- 2.4.x (previous minor)
- 1.x.x (previous major, best-effort)
- Declared minimum (always tested)

## Setup (One-Time)

### GitHub Release Notifications

Subscribe to releases for each integration:
1. Visit repository
2. Click "Watch" → "Custom" → "Releases"

Repositories:
- https://github.com/openai/openai-python
- https://github.com/joaomdmoura/crewAI
- https://github.com/microsoft/autogen
- https://github.com/langchain-ai/langchain
- https://github.com/langchain-ai/langgraph

### Community Channels

Join for early announcements:
- OpenAI Community: https://community.openai.com
- CrewAI Discord: https://discord.gg/crewai
- AutoGen Discord: https://discord.gg/autogen
- LangChain Discord: https://discord.gg/langchain

## Files Reference

```
.github/
├── dependabot.yml                              # Dependency updates
├── workflows/
│   ├── integration-compatibility-matrix.yml   # Version testing
│   └── monitor-upstream-releases.yml          # Release alerts
└── ISSUE_TEMPLATE/
    └── integration-compatibility.md           # Issue template

scripts/
└── check_upstream_changes.py                  # Manual checking

tenuo-python/tests/integration/
├── test_smoke.py                              # API contract tests
└── README.md                                  # Test documentation

docs/
└── compatibility-matrix.md                    # User-facing version info
```

## Metrics

Track weekly:
- Time to detect breaking change (target: <7 days)
- Time to fix compatibility (target: <14 days)
- Integration test pass rate (target: >95%)
- User-reported compatibility issues (target: <5/month)

## Related Documentation

- **Users**: See `docs/compatibility-matrix.md` for version compatibility
- **Issues**: Use the "Integration Compatibility" issue template
