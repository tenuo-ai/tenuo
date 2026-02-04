---
name: Integration Compatibility Issue
about: Report compatibility issues with upstream integrations
title: '[Integration] <integration-name> <version> compatibility issue'
labels: integration, bug
assignees: ''
---

## Integration Details

**Integration**: (e.g., OpenAI, CrewAI, LangChain)
**Version**: (e.g., 1.9.4)
**Tenuo Version**: (e.g., 0.1.0b7)
**Python Version**: (e.g., 3.11.5)

## Issue Description

<!-- Clear description of the compatibility issue -->

## Error Message

```
Paste full error/traceback here
```

## Reproduction

```python
# Minimal code to reproduce the issue
from tenuo.crewai import GuardBuilder

# ... rest of reproduction
```

## Expected Behavior

<!-- What should happen -->

## Actual Behavior

<!-- What actually happens -->

## Checklist

- [ ] I've checked the [Compatibility Matrix](../../docs/compatibility-matrix.md) for known issues
- [ ] I've searched [existing issues](https://github.com/tenuo-ai/tenuo/issues?q=label%3Aintegration)
- [ ] I've tested with the minimum supported version (if applicable)
- [ ] I've reviewed the upstream changelog for breaking changes

## Upstream Resources

<!-- Link to relevant upstream changelog entries, if known -->
- Upstream changelog:
- Related upstream issue (if any):

## Additional Context

<!-- Any other context about the problem -->
