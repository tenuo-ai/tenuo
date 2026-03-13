# Formal Verification of Tenuo capability Constraints

Formal Verification proves that Tenuo's Protocol properties—monotonicity, constraints, and key-management—are mathematically sound. Our approach uses bounded algebra to discover logical limits, and empirical fuzzing to prove the implementation natively adheres to those limits.

### A Tripartite Approach to Assurance

1. **Alloy Analyzer Models (`aat_constraints.als`)**
   We utilize structural analysis to prove that topological capability relationships (`All`, `Any`, `Not`) securely enforce recursive subsets up to a bounded induction limit. Rather than proving unbounded recursion or generic containment, our models verify that strict **type-keyed positional mapping** (where modified constraints must share exact parent constraint types) securely prevents logical privilege expansion.

2. **Z3 String and Numeric Bounds (`z3_bounds.py`)**
   SMT solving is deployed to prove complex algebraic boundaries for values executing over string and numeric theories. This covers:
   - Defining the strict execution envelope `(parent) && (child)` for `CEL` to preserve precedence constraints.
   - Proving topological subsets over numerical `Range`.
   - Ensuring `CIDR` bit trick masks behave statically as mathematically-contiguous boundaries.
   - Generating worst-case mathematical invariants for bounded suffix (`UrlPattern`) string operations.
   *Note: These Z3 theorems represent "bounded axioms". They mathematically prove the bounds, but they do not prove that code executes those bounds.*

3. **Rust Oracle Verification (`conformance.rs`)**
   To bridge the abstract theories to reality, we use a continuous fuzzer over the native Rust runtime engines. The Rust Oracle probabilistically sweeps `proptest` generator shapes directly against `validate_attenuation`.
   - `CEL` logic must actively reject structurally valid ASTs that exceed the Z3 `(P) && (C)` limit.
   - The hierarchical abstract parsing tree natively filters out type-key mismatch expansions, directly validating the Alloy models in real execution cycles.
