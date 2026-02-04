# Integration Maintenance System

**Status**: Implemented
**Date**: 2026-02-03

## Overview

Automated system to track and respond to API changes in upstream integration libraries (OpenAI, CrewAI, AutoGen, LangChain, LangGraph).

## Components

### Automated Monitoring

1. **Dependabot** (`.github/dependabot.yml`)
   - Weekly dependency update PRs (Monday 9am UTC)
   - Grouped by integration
   - Ignores patch updates

2. **Compatibility Matrix** (`.github/workflows/integration-compatibility-matrix.yml`)
   - Tests minimum and latest versions weekly
   - Runs on integration file changes
   - Auto-creates issues on failures

3. **Release Monitor** (`.github/workflows/monitor-upstream-releases.yml`)
   - Daily checks for new releases (8am UTC)
   - Searches for breaking change keywords
   - Auto-creates issues with changelogs

4. **Smoke Tests** (`tenuo-python/tests/integration/test_smoke.py`)
   - Verifies API contracts haven't changed
   - Tests imports, constructors, basic methods
   - Runs in CI matrix

5. **Manual Script** (`scripts/check_upstream_changes.py`)
   - On-demand changelog checking
   - Keyword search for breaking changes
   - Configurable time window

### Documentation

- `docs/compatibility-matrix.md` - Version compatibility table
- `docs/integration-monitoring.md` - Maintenance procedures
- `.github/ISSUE_TEMPLATE/integration-compatibility.md` - Issue template

## Setup Required

### GitHub Release Notifications (5 minutes)

Subscribe to releases for each integration:
1. Visit repository (e.g., https://github.com/openai/openai-python)
2. Click "Watch" → "Custom" → "Releases"

Repositories:
- https://github.com/openai/openai-python
- https://github.com/joaomdmoura/crewAI
- https://github.com/microsoft/autogen
- https://github.com/langchain-ai/langchain
- https://github.com/langchain-ai/langgraph

### Community Channels (10 minutes)

Join for early announcements:
- OpenAI Community: https://community.openai.com
- CrewAI Discord: https://discord.gg/crewai
- AutoGen Discord: https://discord.gg/autogen
- LangChain Discord: https://discord.gg/langchain

## Usage

### Test Locally

```bash
# Run smoke tests
pytest tenuo-python/tests/integration/test_smoke.py -v

# Check for recent changes
python scripts/check_upstream_changes.py --days 7

# Verbose output
python scripts/check_upstream_changes.py --days 30 -v
```

### Weekly Routine (Monday, 30-60 minutes)

```bash
# Check Dependabot PRs
gh pr list --label dependencies

# Review CI results
gh run list --workflow=integration-compatibility-matrix.yml --limit=1

# Check auto-created issues
gh issue list --label release-alert

# Manual verification
python scripts/check_upstream_changes.py --days 7
```

### Respond to Breaking Changes

1. Review upstream changelog
2. Run tests: `pytest tests/integration/test_smoke.py -k <integration>`
3. Update integration code if needed
4. Update `docs/compatibility-matrix.md`
5. Test examples
6. Update version metadata in integration file

## Maintenance Policy

Tenuo maintains compatibility with:
- Latest major version + previous major
- Latest 2 minor versions within major
- Minimum version declared in `pyproject.toml`

Example: If latest is 2.5.0, support:
- 2.5.x (latest minor)
- 2.4.x (previous minor)
- 1.x.x (previous major, best-effort)
- Declared minimum (always tested)

## Metrics

Track weekly:
- Time to detect breaking change (target: <7 days)
- Time to fix compatibility (target: <14 days)
- Integration test pass rate (target: >95%)
- User-reported compatibility issues (target: <5/month)

## Files

### Configuration
```
.github/
├── dependabot.yml
├── workflows/
│   ├── integration-compatibility-matrix.yml
│   └── monitor-upstream-releases.yml
└── ISSUE_TEMPLATE/
    └── integration-compatibility.md
```

### Scripts & Tests
```
scripts/
└── check_upstream_changes.py

tenuo-python/tests/integration/
├── test_smoke.py
└── README.md
```

### Documentation
```
docs/
├── compatibility-matrix.md
└── integration-monitoring.md
```

## Verification

```bash
# Workflows are valid
gh workflow list | grep -E "(integration|monitor)"

# Smoke tests pass
pytest tenuo-python/tests/integration/test_smoke.py -v

# Script works
python scripts/check_upstream_changes.py --days 7
```

## Recent Findings

As of 2026-02-03, the script detected:
- OpenAI v2.16.0: Contains deprecations
- CrewAI 1.9.0-1.9.3: Multiple releases with changes

Review these releases and test compatibility.

## Support

- Detailed guide: `docs/integration-monitoring.md`
- Version compatibility: `docs/compatibility-matrix.md`
- Issues: Use "Integration Compatibility" template
