# Pattern `**` Security Decision

## Summary

**Decision**: `**` pattern is **reserved and discouraged** in Tenuo.

**Rationale**: Security through explicit intent. `**` is overly permissive and creates attenuation ambiguity.

## Background

The wire format spec previously stated:
> `"**"` matches all paths (recursive glob)

This suggested `**` would be implemented as a valid Pattern constraint, similar to Bash's `globstar` or Python's `**` in pathlib.

## Security Analysis

### 🚨 High Risk: Overly Permissive

```python
# Too easy to grant everything
warrant = Warrant.mint(
    tools=["read_file"],
    path=Pattern("**")  # ← Defeats scoped authorization
)
```

**Problems**:
- Makes it trivial to grant unrestricted access
- Defeats the purpose of capability-based authorization
- Encourages lazy security practices
- Vulnerable to prompt injection attacks

### ⚠️ Attenuation Ambiguity

**Question**: Can `Pattern("*")` attenuate to `Pattern("**")`?

- If `**` is "recursive" and `*` is "single-level", then `**` is BROADER → attenuation would be INVALID
- If `**` matches "any path" and `*` also matches "any string", then they're EQUAL → attenuation would be VALID
- **The semantics are unclear**, leading to implementation bugs and security vulnerabilities

### ⚠️ Semantic Confusion

**What does `**` match exactly?**

Different interpretations:
1. **Bash `**`**: Recursive directory traversal (requires `shopt -s globstar`)
2. **Python `**`**: Matches zero or more directories in `Path.glob()`
3. **String matching**: Matches the literal string `"**"`
4. **Tenuo Pattern**: ???

Without clear semantics:
- `Pattern("**")` might match `/etc/passwd`
- `Pattern("**")` might match `../../secrets`
- Users will be confused and make mistakes

## Better Alternatives

### ✅ Use `Wildcard()` for Unrestricted Access

```python
# Instead of:
Pattern("**")  # ← Unclear, dangerous

# Use:
Wildcard()     # ← Explicit "allow all"
```

**Benefits**:
- **Explicit intent**: `Wildcard()` clearly signals "unrestricted"
- **Audit visibility**: Shows up in logs as "UNRESTRICTED"
- **No ambiguity**: Cannot be confused with scoped patterns
- **Already implemented**: No new code needed

### ✅ Use Specific Patterns for Structured Paths

```python
# Good: Scoped to specific directories
Pattern("/data/project-123/*")
Pattern("/uploads/user-456/*.jpg")
Pattern("/api/v1/*")

# Bad: Overly broad
Pattern("**")  # Just use Wildcard()
```

## Spec Update

### Pattern Attenuation Rules (Updated)

**Removed**:
```markdown
| `"**"` | Any pattern | YES | Double-star (recursive glob) matches all paths |
```

**Added**:
```markdown
**`**` (Double-Star) Pattern:** The `**` pattern is **reserved and discouraged**. 
While `**` conceptually means "match all paths," it creates security risks:
- **Overly permissive**: Makes it too easy to grant unrestricted access
- **Attenuation ambiguity**: Unclear if `**` is "broader" or "equal" to `*`
- **Foot-gun potential**: Users may use `**` when they mean specific scoping

**Recommended alternatives:**
- Use `Wildcard()` constraint for explicit unrestricted access
- Use specific patterns like `/data/*/file` or `/path/**/*.txt` for structured paths
- Implementations MAY reject `Pattern("**")` with an error directing users to `Wildcard()`
```

## Implementation Status

### Current Behavior (tenuo-core)

The Rust implementation **does not** have special handling for `**`:
- `Pattern::new("**")` would create a glob pattern matching the literal `**`
- No special `RecursiveGlob` variant exists
- `**` is treated like any other string pattern

**This is correct behavior** - we're keeping it simple and safe.

### Optional Enhancement

Implementations MAY add an explicit error for `**`:

```rust
impl Pattern {
    pub fn new(pattern: &str) -> Result<Self> {
        // Explicit rejection with helpful message
        if pattern == "**" {
            return Err(Error::InvalidPattern(
                "Pattern(\"**\") is not supported. \
                 Use Wildcard() for unrestricted access, or \
                 use specific paths like \"/data/*/file\"."
                    .to_string(),
            ));
        }
        
        // ... rest of implementation
    }
}
```

**Recommendation**: Add this in v0.2 if users report confusion. For now, the spec warning is sufficient.

## Developer Guidance

### ❌ Don't Do This

```python
# Too broad, unclear semantics
Pattern("**")

# Accidental unrestricted access
warrant = parent.grant_builder().path(Pattern("**"))
```

### ✅ Do This Instead

```python
# Explicit unrestricted access
Wildcard()

# Scoped patterns
Pattern("/data/project-*/")
Pattern("/uploads/user-*/*.jpg")
Pattern("/api/v1/*")

# Path-specific matching
Subpath("/data/projects")  # Secure path containment
```

## Related Patterns

### Pattern Types (Current Implementation)

| Type | Example | Use Case |
|------|---------|----------|
| **Exact** | `"production"` | Single value only |
| **Prefix** | `"staging-*"` | Environments, prefixed resources |
| **Suffix** | `"*-safe"` | File extensions, postfixed resources |
| **Complex** | `"pre-*-suf"`, `"*mid*"` | Requires equality (conservative) |
| **Wildcard** | N/A - use `Wildcard()` | Unrestricted access |

### When to Use Each Constraint

| Need | Use | Example |
|------|-----|---------|
| **Single value** | `Exact("prod")` | Environment name |
| **Prefix matching** | `Pattern("proj-*")` | Project IDs |
| **Suffix matching** | `Pattern("*.pdf")` | File extensions |
| **Path containment** | `Subpath("/data")` | Directory restrictions |
| **Regex matching** | `Regex("^[a-z]+\\.pdf$")` | Complex patterns |
| **Unrestricted** | `Wildcard()` | Testing, root warrants |

## Testing Guidance

### Test Coverage

Implementations SHOULD test:

1. **`Pattern("**")` behavior** - Either:
   - Rejects with helpful error (preferred)
   - Treats as literal string `"**"` (current)

2. **Wildcard alternative** - Verify:
   - `Wildcard()` matches any value
   - `Wildcard()` cannot be attenuated TO (would expand)
   - `Wildcard()` can attenuate to any constraint (narrows)

3. **Pattern attenuation** - Verify:
   - `Pattern("*")` requires equality for attenuation
   - `Pattern("prefix-*")` can narrow to `Pattern("prefix-more-*")`
   - Complex patterns require exact equality

### Example Tests

```python
# Test: Pattern("**") either rejects or treats as literal
try:
    p = Pattern("**")
    assert p.matches("**")  # If allowed, treats as literal
except InvalidPattern as e:
    assert "Wildcard()" in str(e)  # If rejected, helpful message

# Test: Wildcard is the correct alternative
w = Wildcard()
assert w.matches("/etc/passwd")
assert w.matches("anything")
assert w.matches("**")  # Even literal **

# Test: Cannot expand to Wildcard
parent = Pattern("/data/*")
child = Wildcard()
with pytest.raises(MonotonicityViolation):
    parent.validate_attenuation(child)  # Would expand permissions
```

## Documentation Updates

### Files Changed

1. **docs/spec/wire-format-v1.md**:
   - Removed `**` from Pattern attenuation table
   - Added security warning about `**`
   - Recommended `Wildcard()` alternative
   - Updated conformance tests to remove `**`

2. **PATTERN_DOUBLE_STAR_DECISION.md** (this file):
   - Complete security analysis
   - Design rationale
   - Developer guidance

### Files NOT Changed

- **tenuo-core/src/constraints.rs** - No code changes needed (correct behavior)
- **tenuo-python/tenuo/constraints.py** - No code changes needed
- **Tests** - Existing tests don't use `**` (good!)

## Conclusion

**`**` is reserved and discouraged** because:

1. ✅ **Security**: Prevents overly permissive grants
2. ✅ **Clarity**: `Wildcard()` is explicit about intent
3. ✅ **Simplicity**: No complex attenuation rules for `**`
4. ✅ **Correctness**: No semantic ambiguity

**Users should**:
- Use `Wildcard()` for unrestricted access
- Use specific `Pattern("/path/*")` for structured matching
- Use `Subpath("/dir")` for secure path containment

**Implementations should**:
- Document the `**` caveat
- Optionally reject `Pattern("**")` with helpful error
- Keep current conservative Pattern logic

---

**Status**: ✅ Spec updated, decision documented  
**Impact**: Low (no code changes needed)  
**Breaking**: No (existing behavior unchanged)  
**Security**: Improved (prevents foot-gun)
