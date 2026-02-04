# Integration Smoke Tests

This directory contains smoke tests that verify the basic API contracts of upstream integrations haven't changed.

## Purpose

These tests detect breaking changes in upstream libraries by:
1. Verifying core class constructors still work
2. Checking that expected attributes/methods exist
3. Testing basic functionality

## Running Tests

```bash
# Test all integrations with currently installed versions
pytest tests/integration/test_smoke.py -v

# Test specific integration
pytest tests/integration/test_smoke.py -k openai -v

# Test with specific version
pip install crewai==1.9.0
pytest tests/integration/test_smoke.py -k crewai -v
```

## Adding New Integration Tests

When adding a new integration:

1. Add import test:
```python
def test_myintegration_import():
    """Verify MyIntegration can be imported."""
    try:
        import myintegration
        assert myintegration is not None
    except ImportError:
        pytest.skip("myintegration not installed")
```

2. Add constructor tests for key classes:
```python
def test_myintegration_client_creation():
    """Verify client constructor signature."""
    try:
        from myintegration import Client

        client = Client(api_key="test")
        assert hasattr(client, 'expected_method')
    except ImportError:
        pytest.skip("myintegration not installed")
```

3. Add to CI matrix in `.github/workflows/integration-compatibility-matrix.yml`

## What These Tests Don't Do

- ❌ Test Tenuo integration code (that's in `tests/test_*.py`)
- ❌ Test actual API calls (use mocks)
- ❌ Test complex workflows

## What These Tests Do

- ✅ Detect breaking changes in upstream APIs
- ✅ Verify basic class/method existence
- ✅ Print version information for debugging
- ✅ Run fast (no network calls)

## Interpreting Results

**Test passes**: Upstream API is stable
**Test fails**: Breaking change detected, investigate:
1. Check upstream changelog
2. Update Tenuo integration code
3. Update minimum version in pyproject.toml

## Automation

These tests run automatically:
- **Weekly**: On Monday 9am UTC
- **On PR**: When integration files change
- **On Demand**: Via `gh workflow run`
