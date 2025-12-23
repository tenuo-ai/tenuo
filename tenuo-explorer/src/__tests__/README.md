# Test Suite Documentation

## Philosophy

These tests verify **API compliance**, not just absence of old patterns. They ensure generated code:
1. **Actually works** with the current Tenuo API
2. **Includes all required components** (imports, parameters, methods)
3. **Follows current best practices** (PoP signatures, serialization)

## When API Changes

If the Tenuo Python or Rust API changes:

1. **Update the code generator** in `App.tsx`
2. **Update these tests** to match the new API
3. **Run tests** to verify compliance

### Example: If `Warrant.issue()` signature changes

```typescript
// OLD API (hypothetical)
warrant = Warrant.issue(keypair=key, capabilities=caps, ttl_seconds=3600)

// NEW API (hypothetical)
warrant = Warrant.issue(issuer=key, tools=tools, duration=3600)
```

**Update tests to verify:**
```typescript
it('passes issuer parameter', () => {
  expect(code).toContain('issuer=');
});

it('passes tools parameter', () => {
  expect(code).toContain('tools=');
});

it('passes duration parameter', () => {
  expect(code).toContain('duration=');
});
```

## Test Categories

### 1. **Required Imports**
Verifies all necessary classes/types are imported.

### 2. **Warrant Issuance**
Verifies the warrant creation API is used correctly with all required parameters.

### 3. **Constraint Definition**
Verifies constraints are defined using the current API.

### 4. **Authorization Flow**
Verifies PoP signature creation and authorization calls.

### 5. **Serialization**
Verifies warrant serialization for transmission.

### 6. **Code Structure**
Verifies generated code is syntactically valid and well-commented.

## Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test CodeGeneration.test.ts

# Watch mode
npm test -- --watch

# Coverage
npm run test:coverage
```

## Maintenance

**Review these tests whenever:**
- Tenuo API changes
- Code generator is modified
- New features are added to generated code
- Documentation is updated

**Goal:** Keep tests in sync with actual working code, not historical patterns.
