# Integration Monitoring & Maintenance

Procedures for maintaining compatibility with upstream integration libraries.

## Automated Systems

### Dependabot
- **File**: `.github/dependabot.yml`
- **Schedule**: Weekly (Monday 9am UTC)
- **Action**: Creates PRs for version updates
- **Grouping**: Updates grouped by integration

### Compatibility Matrix Testing
- **File**: `.github/workflows/integration-compatibility-matrix.yml`
- **Schedule**: Weekly + on integration file changes
- **Tests**: Minimum and latest versions
- **Action**: Auto-creates issues on failures

### Release Monitoring
- **File**: `.github/workflows/monitor-upstream-releases.yml`
- **Schedule**: Daily (8am UTC)
- **Detection**: Searches for "breaking", "removed", "deprecated"
- **Action**: Auto-creates issues with changelogs

### Smoke Tests
- **File**: `tenuo-python/tests/integration/test_smoke.py`
- **Purpose**: Verify API contracts
- **Coverage**: Imports, constructors, basic methods
- **Run**: `pytest tests/integration/test_smoke.py -v`

## Manual Checking

Use the script for on-demand checks:

```bash
# Check all integrations (last 7 days)
python scripts/check_upstream_changes.py

# Specific integration
python scripts/check_upstream_changes.py --integration crewai

# Longer window
python scripts/check_upstream_changes.py --days 30

# Verbose with previews
python scripts/check_upstream_changes.py -v
```

## Weekly Workflow

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
6. Update version metadata in integration file

## Version Metadata

Each integration file should include:

```python
"""
Compatibility:
    <Integration>: X.Y.Z - A.B.C
    Last tested: X.Y.Z (YYYY-MM-DD)
    Python: 3.9+

Known Issues:
    None

Next Breaking Change:
    <Integration> X.0 (expected QYYYY): Description
"""
```

## Community Engagement

**Upstream Communities**:
- OpenAI Community: https://community.openai.com
- CrewAI Discord: https://discord.gg/crewai (#announcements)
- AutoGen Discord: https://discord.gg/autogen (#announcements)
- LangChain Discord: https://discord.gg/langchain (#announcements)

**GitHub Release Watching**:
- Go to repository
- Click "Watch" → "Custom" → "Releases"

## Support Policy

Tenuo maintains compatibility with:
- Latest major version + previous major
- Latest 2 minor versions within major
- Minimum version declared in `pyproject.toml`

## Escalation

- **P0** (Blocks users): Fix within 48 hours
- **P1** (Workaround exists): Fix within 1 week
- **P2** (Minor impact): Fix in next release

## Resources

- Compatibility Matrix: `docs/compatibility-matrix.md`
- Smoke Tests: `tests/integration/test_smoke.py`
- Issue Template: `.github/ISSUE_TEMPLATE/integration-compatibility.md`
