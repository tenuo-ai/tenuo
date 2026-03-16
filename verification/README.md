# Formal Verification of the Attenuation Algebra

Tenuo's authorization model relies on a core invariant: when a warrant is
attenuated (delegated with narrower permissions), the child's accepted values
must be a **strict subset** of the parent's. Any violation is a privilege
escalation.

This directory contains the formal verification artifacts that prove this
invariant holds. Three complementary techniques target different layers:

| Layer | Tool | What it proves |
|-------|------|----------------|
| **Design** | [Alloy](#alloy-bounded-model-checking) | Monotonicity of the attenuation lattice for set-theoretic constraint types |
| **Design** | [Z3/SMT](#z3smt-solver) | Monotonicity for constraints requiring domain-specific arithmetic (Range, CIDR, CEL, UrlPattern) |
| **Implementation** | [Proptest](#property-based-testing-proptest) | The Rust implementation preserves monotonicity under random fuzzing, plus wire-format and enforcement invariants |

## Alloy (bounded model checking)

**File:** [`aat_constraints.als`](aat_constraints.als)

Models 9 constraint types with set-theoretic semantics:

- **Exact**, **Wildcard**, **OneOf**, **NotOneOf** - finite value sets
- **Contains**, **Subset** - list-valued constraints
- **Not**, **Any**, **All** - composite/logical operators

The `subsumes_step` predicate mirrors `validate_attenuation` from the Rust
implementation. Depth-3 recursion is supported for nested `All` constraints via
the `sub1`/`sub2`/`sub3` function chain.

**Assertions:**

- `CapabilityMonotonicity` - if the model accepts an attenuation, then
  `child.accepts ⊆ parent.accepts`. Checked for scope 8 Constraint, 8 Value.
  Result: **UNSAT** (no counterexample exists).

- `MapMonotonicity` - models the I4 keyset identity rule (IETF draft
  Section 4.5). A `ConstraintMap` maps `ArgKey` to `Constraint`. When the
  parent map is non-empty, the child must have exactly the same key set;
  when the parent is empty (open-world), the child may introduce any keys.
  Per-key constraints must subsume. Under closed-world `map_accepts`
  semantics, if `map_subsumes(parent, child)` holds, then every argument
  vector accepted by the child map is also accepted by the parent map.
  Checked for scope 4 Constraint, 4 Value, 3 ArgKey, 4 ConstraintMap.
  Result: **UNSAT** (no counterexample exists).

- `conservatism_gap` - enumerates attenuations that are semantically valid but
  intentionally rejected by the implementation (e.g., cross-type pairs). This is
  a `run` command, not an assertion - it documents the gap rather than asserting
  its absence.

**Running:**

```bash
java -jar alloy.jar exec aat_constraints.als
```

**Not modeled:** Range, Pattern, Regex, Subpath, Shlex, UrlSafe, Cidr,
UrlPattern, CEL. These require value-domain structure (ordering, string
matching, IP arithmetic) that Alloy's relational logic cannot express. They are
covered by Z3 and proptest instead.

## Z3/SMT solver

**File:** [`z3_bounds.py`](z3_bounds.py)

Proves monotonicity for constraint types that need domain-specific reasoning:

- **Range -> Range** - integer interval containment via `ForAll` over `Int`
- **Range -> Exact** - point-in-interval check
- **CIDR -> CIDR** - IP subnet containment via 32-bit bitvector mask arithmetic
- **CEL conjunction** - `(parent) && (extra)` implies `parent` (boolean logic)
- **UrlPattern -> UrlPattern** - domain suffix and path prefix narrowing via
  Z3 string theory

Each theorem is proved by checking that no counterexample exists (the negation
is UNSAT).

**Running:**

```bash
pip install z3-solver
python verification/z3_bounds.py
```

**Expected output:**

```
--- Range Constraints ---
Checking Range Subsumes Range...
  [+] PROVED: No counterexamples exist.
Checking Range Subsumes Exact...
  [+] PROVED: No counterexamples exist.

--- CIDR Constraints ---
Checking CIDR Subsumes CIDR...
  [+] PROVED: No counterexamples exist.

--- CEL Constraints ---
Checking CEL Conjunction is Monotonic...
  [+] PROVED: No counterexamples exist.

--- URL Pattern Constraints ---
Checking UrlPattern Subsumes UrlPattern...
  [+] PROVED: No counterexamples exist.
```

## Property-based testing (proptest)

**File:** [`../tenuo-core/tests/attenuation_soundness.rs`](../tenuo-core/tests/attenuation_soundness.rs)

Unlike Alloy and Z3 which verify abstract models, proptest fuzzes the **actual
Rust implementation** with randomly generated constraints and values. This
catches implementation bugs that a correct model would miss (off-by-one errors,
missing match arms, serialization issues).

**35 properties** organized into five categories:

### Monotonicity soundness (12 tests)

The core invariant: if `validate_attenuation(parent, child)` returns `Ok`, then
for all values `v`, `child.matches(v) => parent.matches(v)`.

- `prop_attenuation_soundness` - 5000 random constraint pairs
- `prop_same_type_soundness` - dense sampling (20-40 values) for all 10
  same-type pairs including Shlex and UrlSafe
- `prop_cross_type_to_exact_soundness` - parent types that can narrow to Exact
- `prop_wildcard_parent_soundness` - Wildcard as universal parent
- `prop_wider_child_rejected` - Wildcard child always rejected for non-Wildcard parent
- 4 exhaustive tests for finite-domain types (OneOf, NotOneOf, Subset, Contains)
- 3 regression tests for previously discovered bugs:
  - OneOf -> NotOneOf privilege escalation
  - CEL conjunction bypass via operator precedence
  - Not -> Not unsoundness

### Wire format idempotence (3 tests)

`serialize(deserialize(serialize(x))) == serialize(x)` for Constraint,
ConstraintSet, and full Warrant CBOR encoding.

### Enforcement soundness (2 tests)

`in_memory.matches(v)` agrees with `decoded_warrant.check_constraints(v)` after
a serialization round-trip, for both single-field and multi-field scenarios.

### Closed-world semantics and keyset identity (9 tests)

- Unknown fields rejected when `allow_unknown = false`
- Unknown fields permitted when `allow_unknown = true`
- `allow_unknown` cannot be widened during attenuation
- Both states survive wire round-trip
- Adding a key to a non-empty parent map rejected (I4 keyset identity)
- Adding keys to an empty parent map accepted (open-world transition)
- Dropping a key from a non-empty parent map rejected (I4 keyset identity)

### TTL and constants (5 tests)

- `expires_at` preserved exactly across wire
- Child TTL <= parent TTL after decode
- Expired warrants remain expired after round-trip
- `MAX_WARRANT_SIZE` and `MAX_CONSTRAINT_DEPTH` enforced at decode time

**Running:**

```bash
cd tenuo-core
cargo test --test attenuation_soundness --all-features -- --nocapture
```

This test is also run in CI on every push.

## Coverage summary

| Constraint type | Alloy | Z3 | Proptest |
|----------------|-------|-----|---------|
| Exact          | Yes   | -   | Yes     |
| Wildcard       | Yes   | -   | Yes     |
| OneOf          | Yes   | -   | Yes     |
| NotOneOf       | Yes   | -   | Yes     |
| Contains       | Yes   | -   | Yes     |
| Subset         | Yes   | -   | Yes     |
| Not            | Yes   | -   | Yes     |
| Any            | Yes   | -   | Yes     |
| All            | Yes   | -   | Yes     |
| Range          | -     | Yes | Yes     |
| Pattern        | -     | -   | Yes     |
| Regex          | -     | -   | Yes     |
| Subpath        | -     | -   | Yes     |
| Shlex          | -     | -   | Yes     |
| UrlSafe        | -     | -   | Yes     |
| Cidr           | -     | Yes | Yes     |
| UrlPattern     | -     | Yes | Yes     |
| CEL            | -     | Yes | Yes     |

Every constraint type is covered by at least one formal method. The
set-theoretic types have proofs at the design level (Alloy). The
domain-specific types have proofs via SMT (Z3). All types are fuzzed against
the real implementation (proptest).
