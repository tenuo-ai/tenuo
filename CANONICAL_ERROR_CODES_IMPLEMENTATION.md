# Canonical Error Codes Implementation - Complete ✓

## Summary

Successfully implemented a unified canonical error code system across all Tenuo components using an elegant decorator pattern.

## What Was Done

### 1. Rust Implementation ✓

**File**: `tenuo-core/src/error.rs`

- Added `ErrorCode` enum with `#[repr(u16)]` for numeric codes (1000-2199)
- Implemented derivation methods:
  - `code()` → numeric wire code
  - `name()` → kebab-case name
  - `description()` → human-readable description
  - `http_status()` → HTTP status code mapping
- Added `Error::to_error_code()` for mapping Rust errors to canonical codes
- Added comprehensive unit tests

### 2. Python Implementation ✓

**File**: `tenuo-python/tenuo/exceptions.py`

- Added `ErrorCode` enum (Python mirror of Rust)
- Created `ERROR_CODE_REGISTRY` dict for exception → code mapping
- Implemented `@wire_code(code)` decorator for automatic registration
- Added methods to `TenuoError`:
  - `get_wire_code()` → numeric code
  - `get_wire_name()` → kebab-case name
  - `get_http_status()` → HTTP status
- Updated `to_dict()` to include wire codes
- Applied `@wire_code` decorators to 63 exception classes

### 3. Rust Authorizer ✓

**File**: `tenuo-core/src/bin/authorizer.rs`

- Updated HTTP responses to include:
  - `error` (legacy string for compatibility)
  - `error_code` (new canonical numeric code)
  - `message` (derived description)

### 4. A2A Protocol ✓

**File**: `tenuo-python/tenuo/a2a/errors.py`

- Updated JSON-RPC error responses to include `tenuo_code` in `data` field
- Added `from_wire_code()` method for reverse mapping

### 5. FastAPI Integration ✓

**File**: `tenuo-python/tenuo/fastapi.py`

- Added global exception handler for `TenuoError`
- Returns structured errors with wire codes:
  ```json
  {
    "error": "constraint-violation",
    "error_code": 1501,
    "message": "...",
    "details": {}
  }
  ```

### 6. Tests ✓

**File**: `tenuo-python/tests/test_exception_wire_codes.py`

- 37 comprehensive tests covering:
  - Registry completeness (all exceptions registered)
  - Code values (correct numeric codes)
  - Name generation (kebab-case formatting)
  - HTTP status mapping
  - Backwards compatibility
  - Error serialization

**Result**: All 37 tests passing ✓

### 7. Documentation Updates ✓

Updated all integration docs with error handling sections:

- **FastAPI** (`docs/fastapi.md`) - Wire codes with HTTP status mapping
- **LangChain** (`docs/langchain.md`) - Typed exceptions with wire codes
- **LangGraph** (`docs/langgraph.md`) - Wire codes for direct exception handling
- **MCP** (`docs/mcp.md`) - Structured errors with wire codes
- **A2A** (`docs/a2a.md`) - JSON-RPC + wire codes in data field
- **OpenAI** (`docs/openai.md`) - Custom errors with note on wire codes
- **Google ADK** (`docs/google-adk.md`) - Custom errors with structured responses

### 8. Wire Format Specification ✓

**File**: `docs/spec/wire-format-v1.md`

- Moved error codes to Appendix A
- Added comprehensive error code documentation:
  - A.1: Complete `ErrorCode` enum
  - A.2: HTTP status code mapping
  - A.3: JSON-RPC error code mapping
  - A.4: Example error responses for HTTP and JSON-RPC

## Design Elegance

### The Decorator Pattern

The solution uses a decorator pattern for automatic registration:

```python
@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class ConstraintViolation(ScopeViolation):
    # ...
```

This provides:
- **Single source of truth**: Wire codes defined once in `ErrorCode` enum
- **Automatic registration**: Decorators populate `ERROR_CODE_REGISTRY`
- **Zero boilerplate**: No manual mapping tables
- **Type safety**: Decorators apply to classes, not instances
- **Maintainability**: Adding new exceptions requires one decorator line

### Cross-Protocol Consistency

All protocols derive from canonical codes:

```
ErrorCode.CONSTRAINT_VIOLATION = 1501
    ↓
├─→ HTTP: 403 Forbidden
├─→ JSON-RPC: -32008
├─→ Wire name: "constraint-violation"
└─→ Description: "Argument violates warrant constraint"
```

## Impact

### For Developers
- **Machine-readable errors**: Clients can programmatically handle specific errors
- **Consistent debugging**: Same error codes across HTTP, JSON-RPC, gRPC
- **Precise error handling**: Know exactly what went wrong (1501 vs 1502)

### For Integration Authors
- **Automatic support**: Most integrations inherit wire codes via `TenuoError`
- **Minimal changes**: Only FastAPI needed an exception handler
- **Type safety**: Python's type system enforces correct usage

### For Operators
- **Cross-protocol logs**: Search for "1501" finds all constraint violations
- **Alerting**: Trigger on specific wire codes, not strings
- **Dashboarding**: Group errors by code ranges (1000s, 1500s, etc.)

## Backwards Compatibility

All changes maintain backwards compatibility:

- Rust authorizer includes both legacy `error` string and new `error_code` numeric
- Python `TenuoError.to_dict()` includes both `error_code` (snake_case) and `wire_code` (numeric)
- A2A includes `tenuo_code` in `data` field, doesn't change top-level structure

## Files Changed

### Rust
- `tenuo-core/src/error.rs` (major refactor)
- `tenuo-core/src/bin/authorizer.rs` (minor update)

### Python
- `tenuo-python/tenuo/exceptions.py` (major refactor + 63 decorators)
- `tenuo-python/tenuo/fastapi.py` (added exception handler)
- `tenuo-python/tenuo/a2a/errors.py` (added wire code in responses)
- `tenuo-python/tests/test_exception_wire_codes.py` (new file, 37 tests)

### Documentation
- `docs/spec/wire-format-v1.md` (Appendix A: Error Codes)
- `docs/fastapi.md` (Error Handling section)
- `docs/langchain.md` (Wire Code Support)
- `docs/langgraph.md` (Wire Code Support)
- `docs/mcp.md` (Error Handling section)
- `docs/a2a.md` (Wire Code Support)
- `docs/openai.md` (Error Reference update)
- `docs/google-adk.md` (Error Handling section)

## Next Steps (Optional)

1. **Metrics**: Track error code distribution in production
2. **Client Libraries**: Add wire code parsers to client SDKs
3. **Alerting**: Set up Grafana/Datadog alerts on critical codes (1100, 1300, 1800)
4. **Documentation**: Add error code quick reference to main README

## Verification

Run tests:
```bash
cd tenuo-python
python3 -m pytest tests/test_exception_wire_codes.py -v
# Result: 37 passed ✓
```

Check integration:
```bash
cd tenuo-python
python3 -c "
from tenuo.exceptions import SignatureInvalid, ConstraintViolation, ERROR_CODE_REGISTRY
print(f'SignatureInvalid: {SignatureInvalid('test').get_wire_code()}')  # 1100
print(f'ConstraintViolation: {ConstraintViolation('f', 'r').get_wire_code()}')  # 1501
print(f'Total registered: {len(ERROR_CODE_REGISTRY)}')  # 63+
"
```

---

**Status**: ✅ Complete and tested
**Elegance**: ✅ Decorator pattern with automatic registration
**Compatibility**: ✅ Backwards compatible
**Coverage**: ✅ All 7 integrations documented
