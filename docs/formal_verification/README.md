# Formal Verification of Tenuo Capability Constraints

Tenuo's core security invariant is **capability monotonicity** (I4 in the AAT spec): if
`validate_attenuation(parent, child)` succeeds, then every value accepted by `child` is also
accepted by `parent`. No attenuation step can widen access.

Proving this end-to-end requires three complementary layers. Each layer has a different scope
and failure mode; together they give a defense-in-depth assurance argument.

---

## Layer 1 — Alloy bounded model checking (`aat_constraints.als`)

**What it proves:** For the set-theoretic constraint types (`Exact`, `Wildcard`, `OneOf`,
`NotOneOf`, `Contains`, `Subset`, `Not`, `Any`, `All`), the subsumption rules are
set-monotone — `child.accepts ⊆ parent.accepts` — whenever the structural check passes.

**Method:** Fixed-point iteration over a parametric `subsumes_step` predicate. The relation
is unrolled eight times (`sub1`–`sub8`), and the `CapabilityMonotonicity` assertion is
checked against the `sub8` fixed point:

```alloy
assert CapabilityMonotonicity {
    all parent, child: Constraint |
        parent->child in sub8 => (child.accepts in parent.accepts)
}
check CapabilityMonotonicity for 8 Constraint, 8 Value
```

Alloy exhausts the entire state space up to 8 constraints and 8 values, finding no
counterexamples.

**Key rules verified:**
- `All → All`: injective type-keyed mapping from every parent clause to a distinct child clause
  (child must attenuate each parent clause)
- `Any → Any`: injective type-keyed mapping from every child clause to a distinct parent clause
  (child may drop clauses, never add)
- `Not → Not`: subsumption direction is reversed on the inner constraint
- All leaf types: `Exact`, `OneOf`, `NotOneOf`, `Contains`, `Subset` follow their algebraic rules

**Known divergence from the runtime:** The Alloy model encodes the *semantic* subsumption
rules for `Any` and `Not`. The Rust runtime is intentionally more conservative: it rejects
`Any → Any` and `Not → Not` entirely, pending a JCS-canonical identity comparison
implementation. This is documented in `conformance.rs` and reflected in
`exhaustive_anyof_anyof_always_rejected` / `exhaustive_not_not_always_rejected`. The
divergence is a capability limitation, not a soundness hole: the runtime never incorrectly
*accepts* a widening attenuation.

---

## Layer 2 — Z3 SMT proofs for domain-specific types (`z3_bounds.py`)

**What it proves:** For constraint types whose semantics live in string or numeric theories
(not reducible to pure set membership), Z3 proves the monotonicity invariant directly over
those theories.

**Scope:** These are *bounded axioms* — they prove that the abstract algebraic model of each
constraint type is monotone. They do not model the full CEL parser, the complete glob engine,
or the regex state machine. The conformance oracle (Layer 3) connects the axioms to the
actual implementations.

### Theorems proved

| Constraint | Theorem | Method |
|---|---|---|
| `Range` (integer) | Child interval `[cmin, cmax] ⊆ [pmin, pmax]` implies every value in the child interval is in the parent interval | `BitVec(64)` arithmetic |
| `Range` (exact) | An exact value within parent bounds is accepted by a range parent | `Int` arithmetic |
| `CIDR` | If `child_mask` is at least as specific as `parent_mask` and `child_net` falls inside the parent network, then every IP in the child subnet is in the parent subnet | 32-bit bitmask algebra |
| `CEL` (valid form) | `(P) && (C)` always implies `P` | Uninterpreted `SatisfiesCEL` function with conjunction axiom |
| `CEL` (attack form) | `(P) && C \|\| E` does *not* always imply `P` | Satisfiable counterexample: `eval_p=False`, `eval_e=True` |
| `Pattern` (prefix wildcard) | `PrefixOf(parent_prefix, child_prefix)` transitively implies `PrefixOf(parent_prefix, v)` whenever `PrefixOf(child_prefix, v)` | Z3 sequence theory |
| `Pattern` (suffix wildcard) | `SuffixOf(parent_suffix, child_suffix)` transitively implies `SuffixOf(parent_suffix, v)` whenever `SuffixOf(child_suffix, v)` | Z3 sequence theory |
| `Subpath` | `PrefixOf(parent, child)` subsumption is transitive | Z3 sequence theory |
| `UrlPattern` | Domain suffix and path prefix subsumption are each transitive | Z3 sequence theory |
| `UrlSafe` | Child's allowed set is a subset of parent's allowed set; child's denied set is a superset of parent's denied set | Uninterpreted set functions with `ForAll` axioms |

**f64 edge cases:** Z3's `BitVec` and `Int` theories model integer arithmetic only. IEEE 754
edge cases (NaN, ±∞, −0.0, subnormals) are not representable in these theories. These are
covered exhaustively at the Rust layer by `exhaustive_f64_boundaries_soundness` in
`attenuation_soundness.rs`.

---

## Layer 3 — Rust property-based and exhaustive tests

Four test files form the runtime verification layer.

### `attenuation_soundness.rs` — primary soundness engine

The central harness is `assert_monotonicity`, which is fail-closed: a parent evaluation error
is treated as `false`, so any `validate_attenuation` acceptance that results in
`child.matches(v) = true, parent.matches(v) = false` is a hard failure.

**Property-based tests (proptest):**

| Test | Cases | Coverage |
|---|---|---|
| `prop_attenuation_soundness` | 5,000 | All constraint type pairs, random values |
| `prop_same_type_soundness` | 5,000 | All same-type pairs, including `All→All`, composite nesting |
| `prop_cross_type_to_exact_soundness` | 5,000 | Types that narrow to `Exact` |
| `prop_wildcard_parent_soundness` | 5,000 | Wildcard parent with any child |
| `prop_wider_child_rejected` | 5,000 | Wildcard and wider OneOf children must be rejected |

Inner strategies use `composite_leaf_constraint_strategy()` to generate depth-2 composite
nesting (e.g., `All(All([Exact("a")]))`) within All/Any/Not clauses.

**Exhaustive finite-domain tests:**

| Test | What it exhausts |
|---|---|
| `exhaustive_oneof_oneof_soundness` | Every pair of non-empty subsets of ATOMS |
| `exhaustive_notoneof_notoneof_soundness` | Every pair of non-empty subsets |
| `exhaustive_oneof_notoneof_always_rejected` | Cross-type pair always rejected |
| `exhaustive_subset_subset_soundness` | Every pair × every possible list value |
| `exhaustive_contains_contains_soundness` | Every pair × every possible list value |
| `exhaustive_not_not_always_rejected` | Identity and varied inners always rejected |
| `exhaustive_anyof_anyof_always_rejected` | All non-empty clause combinations always rejected |
| `exhaustive_f64_boundaries_soundness` | NaN, ±0.0, ±1.0, ±∞ as both bounds and test values |

**Additional properties verified:** CBOR round-trip idempotence; enforcement agreement with
in-memory `matches()` after wire decode; closed-world unknown-field rejection; `allow_unknown`
narrowing/widening rules; TTL preservation and monotonicity across wire boundaries;
`MAX_WARRANT_SIZE` and `MAX_CONSTRAINT_DEPTH` enforcement at decode time.

### `chain_verification_invariants.rs` — chain-level adversarial tests

Tests the six AAT invariants (I1–I6) under adversarial conditions:

- Forged signatures, wrong issuer, mismatched holder
- `parent_hash` chain integrity (splice, truncation, reorder attacks)
- I2 violation: `child.del_max_depth > parent.del_max_depth` (depth escalation)
- Cross-chain capability injection

### `invariants.rs` — high-level warrant invariants

Property-based tests for TTL monotonicity across attenuations, delegation depth increments,
pattern and range widening rejection, and signature integrity.

### `conformance.rs` — conformance oracle

Bridges the abstract Z3/Alloy models to the concrete runtime. Tests that:

- The CEL structural check rejects the `(P) && C || E` attack form
- `All → All` type-keyed matching accepts/rejects correctly
- CIDR network algebra is implemented correctly in the Rust engine
- `Any → Any` conservative rejection matches the documented divergence from the Alloy model

---

## Coverage summary

| Invariant | Alloy | Z3 | proptest |
|---|---|---|---|
| Capability monotonicity (I4) | ✓ sub8 | ✓ per-type | ✓ 5,000+ cases |
| CEL precedence safety | — | ✓ valid + attack | ✓ regression test |
| f64 Range edge cases | — | — (integers only) | ✓ exhaustive |
| Chain integrity (I1–I6) | — | — | ✓ adversarial |
| Wire round-trip fidelity | — | — | ✓ CBOR idempotence |
| Closed-world semantics | — | — | ✓ exhaustive |
| Any/Not conservative rejection | ✓ (semantic model) | — | ✓ exhaustive |

---

## Known limitations

1. **Z3 Range is integer-only.** The SMT proofs use `BitVec(64)` and `Int`. IEEE 754
   semantics (NaN ordering, signed zero, subnormals) require separate handling, provided by
   `exhaustive_f64_boundaries_soundness`.

2. **Any/Not always rejected.** The runtime rejects `Any → Any` and `Not → Not` even for
   identical constraints, pending JCS-canonical identity comparison. This is a conservatism in
   expressiveness, not in soundness: a violation of monotonicity in the permissive direction
   cannot occur.

3. **Alloy scope bound.** The model is checked up to 8 constraints and 8 values. Larger
   structures are handled by the proptest layer, which generates arbitrary-depth compositions.

4. **Z3 CEL and Pattern are abstract.** The Z3 proofs model the algebraic shape of these
   constraints (conjunction semantics, prefix/suffix transitivity), not the full CEL evaluator
   or glob engine. `conformance.rs` verifies the connection to the actual implementations.
