# Formal Verification of Tenuo capability Constraints

Formal Verification proves that Tenuo's Protocol properties—monotonicity, constraints, and key-management—are mathematically sound. Our approach uses bounded algebra to discover logical limits, and empirical fuzzing to prove the implementation natively adheres to those limits.

### A Tripartite Approach to Assurance

1. **Alloy Analyzer Models (`aat_constraints.als`)**
   We utilize structural analysis to prove that topological capability relationships (`All`, `Any`, `Not`) securely enforce recursive subsets up to a bounded induction limit. Our models verify that strict **type-keyed positional mapping** securely prevents logical privilege expansion. *Note: The model and the Rust runtime currently diverge slightly; for example, the Rust runtime conservatively fails `Any -> Any` subset evaluations rather than performing NP-hard subsumption checks, which is documented by our conformance oracle. The identity case is also rejected as a conservative choice; this diverges from spec Section 4.5.*

2. **Z3 String and Numeric Bounds (`z3_bounds.py`)**
   SMT solving is deployed to prove complex algebraic boundaries for values executing over string and numeric theories. This covers:
   - Defining a strict execution envelope `(parent) && (child)` for `CEL` to preserve precedence constraints.
   - Proving topological subsets over numerical `Range`.
   - Ensuring `CIDR` bit trick masks behave statically as mathematically-contiguous boundaries.
   - Abstracting string families (`Regex`, `Pattern`, `UrlPattern`) to bounded prefix/suffix/substring operations.
   *Note: These Z3 theorems represent "bounded axioms". They mathematically prove conservative abstract bounds but are not a complete formal verification of the underlying engines end-to-end (e.g., they do not model the full regex state machine or the complete CEL parser equivalence).*

3. **Rust Oracle Verification (`conformance.rs`)**
   To bridge the abstract theories to reality, we use a continuous fuzzer over the native Rust runtime engines to provide a strong assurance argument:
   - `CEL` logic actively rejects generated malformed structural variants that exceed the Z3 `(P) && (C)` limit (structural fuzzing).
   - The hierarchical abstract parsing tree natively filters out type-key mismatch expansions and asserts the conservative runtime behaviors (like `Any -> Any` failure).
   - Bounded fuzzing probes string theories to ensure structural boundaries are not violated. 
   *(Note: This is intensive behavior-documenting fuzzing, not full semantic equivalence checking between the math and parser implementations.)*
