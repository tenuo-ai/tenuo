# Tenuo Explorer - Testing Guide

## Quick Start

```bash
# Install dependencies
npm install

# Run unit tests
npm test

# Run unit tests with UI
npm run test:ui

# Run E2E tests
npm run test:e2e

# Run all tests
npm run test:all

# Generate coverage report
npm run test:coverage
```

## Test Structure

### Unit Tests (`src/__tests__/`)
- **ExpirationDisplay.test.tsx**: Time formatting and expiration logic
- **CodeGeneration.test.ts**: API regression tests for code generator

### E2E Tests (`e2e/`)
- **explorer.spec.ts**: Critical user flows and regression tests

## Regression Prevention

### What We're Testing For

1. **API Consistency**: Code generator must use current API
   - ✅ Python: `Warrant.issue()` with `capabilities=`
   - ✅ Rust: `Warrant::builder()` with `.build()`
   - ❌ No deprecated `.builder()` in Python
   - ❌ No missing `.build()` in Rust

2. **Time Calculations**: Expiration display accuracy
   - ✅ Correct remaining time
   - ✅ Proper expired state
   - ✅ Accurate formatting (h/m/s)

3. **User Flows**: Critical paths work
   - ✅ Sample loading
   - ✅ Warrant decoding
   - ✅ Authorization checks
   - ✅ Keyboard shortcuts
   - ✅ Mode switching

## Running Tests in CI

Tests run automatically on every push via GitHub Actions.

See `.github/workflows/test.yml` for configuration.

## Coverage Goals

- **Lines**: 70%
- **Functions**: 70%
- **Branches**: 70%
- **Statements**: 70%

## Manual Testing Checklist

Before each release, verify:

- [ ] Sample warrant loads and decodes
- [ ] Authorization check works (dry run)
- [ ] Code generation produces valid Python code
- [ ] Code generation produces valid Rust code
- [ ] Diff viewer compares warrants
- [ ] All keyboard shortcuts work
- [ ] Mode switching works (decoder/builder/chain/diff)
- [ ] Validation warnings appear correctly
- [ ] PoP simulator generates keypairs
- [ ] Timeline visualization displays

## Adding New Tests

### For New Components

1. Create `src/__tests__/ComponentName.test.tsx`
2. Test critical logic and edge cases
3. Add to coverage report

### For New Features

1. Add E2E test to `e2e/explorer.spec.ts`
2. Test happy path and error cases
3. Add regression test if fixing a bug

## Debugging Failed Tests

```bash
# Run specific test file
npm test ExpirationDisplay.test.tsx

# Run tests in watch mode
npm test -- --watch

# Run E2E tests with UI
npm run test:e2e:ui

# View coverage report
open coverage/index.html
```
