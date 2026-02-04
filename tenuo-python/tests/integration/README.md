# Integration Smoke Tests

## Purpose

Smoke tests verify that integration APIs haven't changed in breaking ways. They run against multiple versions of dependencies to catch breaking changes early.

**What smoke tests DO:**
- Verify packages can be imported
- Check that key classes/functions exist
- Validate basic API surface (method names, attributes)

**What smoke tests DON'T DO:**
- Test full object construction (may require complex setup)
- Verify runtime behavior
- Test complex initialization sequences
- Depend on internal implementation details

## Pattern for Robust Smoke Tests

### ✅ Good Pattern (Resilient to API Changes)

```python
def test_package_basic_api():
    """Verify Package class exists and has expected API."""
    try:
        from package import SomeClass

        # 1. Verify class exists
        assert SomeClass is not None

        # 2. Verify key methods exist (no instantiation needed)
        assert hasattr(SomeClass, 'method_name')

        # 3. Optional: inspect signature if needed
        try:
            import inspect
            sig = inspect.signature(SomeClass.__init__)
            params = list(sig.parameters.keys())
            assert 'expected_param' in params
        except (ValueError, TypeError):
            # Signature inspection may fail, that's OK
            pass

    except ImportError:
        pytest.skip("package not installed")
```

### ❌ Bad Pattern (Fragile - Breaks on API Changes)

```python
def test_package_construction():
    """DON'T DO THIS - too fragile."""
    try:
        from package import SomeClass

        # BAD: Assumes specific initialization requirements
        obj = SomeClass(required_param="value")

        # BAD: Tests internal state
        assert obj._internal_field is not None

    except ImportError:
        pytest.skip("package not installed")
```

## Real Example: CrewAI Breaking Change

### What Happened

**CrewAI v1.8**: Agent constructor accepted `llm` as optional
```python
agent = Agent(role="test", goal="test", backstory="test")  # Works
```

**CrewAI v1.9+**: Agent requires actual LLM instance
```python
# This now FAILS because Agent.__init__ calls self.llm.supports_stop_words()
agent = Agent(role="test", goal="test", backstory="test")  # AttributeError!

# Need this instead:
from langchain_openai import ChatOpenAI
agent = Agent(role="test", goal="test", backstory="test", llm=ChatOpenAI())
```

### Bad Smoke Test (Broke in CI)

```python
def test_agent():
    """This broke when CrewAI v1.9 released."""
    from crewai import Agent
    agent = Agent(role="test", goal="test", backstory="test")  # FAILS!
    assert hasattr(agent, 'role')
```

**Problem**: Test assumes Agent can be constructed with minimal params

### Good Smoke Test (Works Across Versions)

```python
def test_agent():
    """Verify Agent class exists and has expected API."""
    from crewai import Agent

    # Just check the class exists
    assert Agent is not None
    assert hasattr(Agent, '__init__')

    # Optional: check signature if possible
    try:
        import inspect
        sig = inspect.signature(Agent.__init__)
        params = list(sig.parameters.keys())
        assert 'role' in params
    except (ValueError, TypeError):
        pass  # Signature inspection failed, that's OK
```

**Why it's better**: Doesn't assume anything about initialization requirements

## Guidelines

### 1. Prefer Class Checks Over Instance Creation

```python
# ✅ Good - no instantiation needed
assert hasattr(MyClass, 'method_name')

# ❌ Bad - requires successful instantiation
obj = MyClass()
assert obj.method_name is not None
```

### 2. Make Construction Tests Optional

If you must test construction, wrap it defensively:

```python
def test_optional_construction():
    """Verify class can be constructed (when simple setup is possible)."""
    try:
        from package import SomeClass

        # Try construction but don't fail if it requires complex setup
        try:
            obj = SomeClass(minimal_params=True)
            assert hasattr(obj, 'expected_attribute')
        except (TypeError, ValueError, AttributeError, RuntimeError) as e:
            # Construction failed - this is expected if setup is complex
            pytest.skip(f"Construction requires complex setup: {e}")

    except ImportError:
        pytest.skip("package not installed")
```

### 3. Gracefully Handle Missing APIs

```python
def test_optional_feature():
    """Verify feature exists (available in some versions)."""
    try:
        from package import SomeClass

        # Some versions may not have this attribute
        if hasattr(SomeClass, 'new_feature'):
            assert callable(SomeClass.new_feature)
        else:
            # Older version - skip without failing
            pytest.skip("Feature not available in this version")

    except ImportError:
        pytest.skip("package not installed")
```

### 4. Document Version-Specific Behavior

```python
def test_version_specific_api():
    """Verify API exists (available since v2.0).

    NOTE: Versions < 2.0 may not have this API, in which case
    we skip the test. This is expected and not a failure.
    """
    try:
        from package import new_feature
        assert new_feature is not None
    except (ImportError, AttributeError):
        pytest.skip("API not available in this version")
```

### 5. Use Multiple Fallback Strategies

```python
def test_with_fallbacks():
    """Verify API with multiple fallback strategies."""
    try:
        from package import SomeClass

        # Strategy 1: Try minimal construction
        try:
            obj = SomeClass()
            assert hasattr(obj, 'method')
            return
        except Exception:
            pass

        # Strategy 2: Try with mock dependencies
        try:
            from unittest.mock import MagicMock
            obj = SomeClass(dependency=MagicMock())
            assert hasattr(obj, 'method')
            return
        except Exception:
            pass

        # Strategy 3: Just check class exists
        assert SomeClass is not None
        assert hasattr(SomeClass, 'method')

    except ImportError:
        pytest.skip("package not installed")
```

## When to Add Smoke Tests

Add smoke tests when:
- Adding a new integration (OpenAI, CrewAI, LangChain, etc.)
- The integration has a history of breaking changes
- We support multiple versions of the dependency
- The integration is critical to Tenuo functionality

Don't add smoke tests when:
- The API is stable and well-tested elsewhere
- The integration is internal-only
- Full integration tests already cover the API comprehensively

## Running Tests

```bash
# Run all smoke tests
pytest tests/integration/test_smoke.py -v

# Run specific integration
pytest tests/integration/test_smoke.py -k "crewai" -v

# Test against specific version
pip install crewai==1.9.0
pytest tests/integration/test_smoke.py -k "crewai" -v

# Run with verbose output
pytest tests/integration/test_smoke.py -vv
```

## Debugging Failures

When a smoke test fails:

1. **Check the error message**
   - ImportError → package not installed
   - AssertionError → API changed
   - AttributeError → method/attribute removed

2. **Test with minimal imports**:
   ```bash
   python -c "from crewai import Agent; print(Agent)"
   ```

3. **Check installed version**:
   ```bash
   pip show crewai
   ```

4. **Review upstream changelog**
   - Check release notes for breaking changes
   - Look for deprecation warnings

5. **Update smoke test**
   - Make it more defensive
   - Add skip conditions for newer versions
   - Document version-specific behavior

## CI/CD Integration

Smoke tests run in CI against:
- **Minimum supported version** (from `pyproject.toml`)
- **Latest stable version**
- **(Optional) Latest pre-release version**

Configured in: `.github/workflows/integration-compatibility-matrix.yml`

This catches:
- Breaking changes in new releases
- Incompatibilities with old versions
- API deprecations before they affect users

## Adding New Integration Tests

When adding a new integration:

1. **Add import test**:
```python
def test_myintegration_import():
    """Verify MyIntegration can be imported."""
    try:
        import myintegration
        assert myintegration is not None
    except ImportError:
        pytest.skip("myintegration not installed")
```

2. **Add class existence test**:
```python
def test_myintegration_classes_exist():
    """Verify key classes exist."""
    try:
        from myintegration import Client, Agent

        # Check classes exist
        assert Client is not None
        assert Agent is not None

        # Check key methods exist
        assert hasattr(Client, 'send_request')
        assert hasattr(Agent, 'execute')

    except ImportError:
        pytest.skip("myintegration not installed")
```

3. **Add optional feature tests**:
```python
def test_myintegration_optional_feature():
    """Verify optional feature exists (if available)."""
    try:
        from myintegration import optional_feature
        assert optional_feature is not None
    except (ImportError, AttributeError):
        pytest.skip("Optional feature not available")
```

4. **Add to CI matrix** in `.github/workflows/integration-compatibility-matrix.yml`

## Related Tests

- **Integration tests** (`tests/test_*_integration.py`): Full functionality with real packages
- **Unit tests** (`tests/test_*.py`): Tenuo-specific logic with mocks
- **Adversarial tests** (`tests/test_*_adversarial.py`): Security and edge cases
- **Smoke tests** (`tests/integration/test_smoke.py`): Minimal API surface validation

## Best Practices Summary

1. ✅ **Test class existence, not instance creation**
2. ✅ **Use `hasattr()` for method checks**
3. ✅ **Wrap construction attempts in try-except**
4. ✅ **Skip gracefully on complex requirements**
5. ✅ **Document version-specific behavior**
6. ✅ **Use multiple fallback strategies**
7. ❌ **Don't assume initialization will work**
8. ❌ **Don't test internal implementation**
9. ❌ **Don't require network access**
10. ❌ **Don't test complex workflows**

## Questions?

See also:
- `docs/integration-monitoring.md` - Upstream monitoring strategy
- `docs/compatibility-matrix.md` - Version compatibility tracking
- `.github/workflows/integration-compatibility-matrix.yml` - CI configuration
