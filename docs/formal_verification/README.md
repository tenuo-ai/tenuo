# Formal checks of the attenuation rules

These models check the central claim of
[draft-niyikiza-oauth-attenuating-agent-tokens-02](../../ietf/draft-niyikiza-oauth-attenuating-agent-tokens-02.md):
a derived token never permits an invocation that its parent denies
(Section 4.5, invariant I4), and a chain is linked hop by hop
(Section 4.6, invariant I5).

## What is checked

| Artifact | Property | Method and scope | Result |
|---|---|---|---|
| [`aat_constraints.als`](aat_constraints.als), `DerivedConstraintNarrows` | A constraint accepted by the Section 4.5 rules accepts only values its parent accepts. Covers the nine core types, with nested `all` and `any`. | Alloy, every instance up to 6 atoms per signature, 4-bit integers | No counterexample |
| `aat_constraints.als`, `DerivedMapNarrows` | A constraint map accepted by the key rules (steps 4p2 to 4p4) allows only invocations its parent allows, with `optional` keys and `"*"`. | Alloy, 3 keys, 2 maps, 1 invocation | No counterexample |
| `aat_constraints.als`, `ChainNarrows` | The same holds from root to leaf across two hops. | Alloy, 3 keys, 3 maps, 1 invocation | No counterexample |
| `aat_constraints.als`, seven `run` commands | The accepted derivation shapes exist, so the assertions above are not vacuous. One command shows a derivation that narrows and is still rejected (Section 4.1). | Alloy, scope 4 or 5 | An instance for every command |
| [`aat_chain_linkage.spthy`](aat_chain_linkage.spthy) | A verifier that checks `par_hash` for every adjacent pair accepts a chain only under the root it was derived from. A verifier that checks the last pair alone does not. | Tamarin, three-token chain, unbounded sessions | Both lemmas verified |
| [`z3_bounds.py`](z3_bounds.py), range | An `exact` value inside a `range` is accepted by the range. | Z3, unbounded integers | Proved |
| `z3_bounds.py`, CIDR | A narrower network inside a parent network accepts only addresses the parent accepts. | Z3, 32-bit vectors | Proved |
| `z3_bounds.py`, URL and path | Domain-suffix, path-prefix and subpath narrowing are transitive. | Z3, unbounded strings | Proved |
| `z3_bounds.py`, CEL | A derived expression of the form `(parent) && (extra)` implies the parent. | Z3, with conjunction given as an axiom | Proved |

CIDR, URL, subpath and CEL are Tenuo extension types. The AAT core types are
the nine in the Alloy model.

## Scope and limits

- An Alloy result holds within the stated scope. It is not a proof for larger
  instances.
- The Alloy model treats numbers as small integers and compares values by
  identity, standing in for JCS equality. The header of the file lists the
  other modeling choices.
- The Tamarin model has no signatures and no adversary. Tokens are fresh names
  and `hash` is a free function. It isolates the linkage rule and says nothing
  about key compromise or proof of possession.
- The CEL lemma checks the shape of the derivation. It does not model CEL
  evaluation.
- No model here covers signatures, proof of possession, expiry or replay. The
  test vectors and the implementation tests below cover those.
- The models are run by hand. The results above are from 2026-11-23 with
  Alloy 6.2.0, Tamarin 1.12.0 and Z3 4.16.0.

## Run them

```bash
# Alloy 6.2.0 (about 80 seconds); the jar is on the Alloy releases page
java -jar alloy.jar exec -f -o /tmp/alloy-out docs/formal_verification/aat_constraints.als

# Tamarin 1.12.0 (under a second)
tamarin-prover --prove docs/formal_verification/aat_chain_linkage.spthy

# Z3 (under a second)
python3 -m pip install z3-solver
python3 docs/formal_verification/z3_bounds.py
```

Alloy prints `UNSAT` for the three `check` commands and `SAT` for the seven
`run` commands. Tamarin prints `verified` for both lemmas. The Z3 script
prints `PROVED` for every lemma.

## Related evidence

- **Property tests of the Rust implementation.**
  [`tenuo-core/tests/attenuation_soundness.rs`](../../tenuo-core/tests/attenuation_soundness.rs)
  runs in CI on every pull request. It generates parent and child constraints
  at random, 5000 cases per property, and checks the set types exhaustively
  over a small domain. These tests exercise the code, where the models above
  exercise the rules.
- **Test vectors.** The [AAT JWS suite](../../ietf/vectors/README.md) has 229
  byte-exact vectors with expected verdicts. Its generator verifies every
  vector with code that shares nothing with Tenuo.
- **Independent implementations.** Verifiers written by other authors from the
  -02 text agree with all 229 verdicts.
  [`INTEROP.md`](../../ietf/vectors/INTEROP.md) lists them with the suite hash
  they ran against.
