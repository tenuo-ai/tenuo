# AAT JWS test vectors

Byte-exact test vectors for the JWS profile of
`draft-niyikiza-oauth-attenuating-agent-tokens` (-02 reading).

| File | Purpose |
|---|---|
| `gen_vectors.py` | Generator. Builds every vector and re-verifies it with its own implementation of the §8 algorithm before writing; that implementation shares no code with Tenuo. |
| `aat-jws-vectors.md` | Human-readable rendering of the suite, kept next to the draft. |
| `compare_results.py` | Compares an implementation's verdicts with the suite and reports every disagreement. |
| `INTEROP.md` | How to run the suite against an implementation and report results, and the results so far. |
| [`../../tests/vectors/aat-jws-vectors.json`](../../tests/vectors/aat-jws-vectors.json) | Machine-readable suite with expected verdict and cited §8 step. The expected verdict follows the -02 text; the step follows §8's order and can differ where §8 permits reordering, so harnesses compare verdicts. Each vector also carries its `presentation` object (§7.4: `aat_chain`, `aat_pop`). |

Both output files are generated. Do not edit them by hand; change the generator
and regenerate.

## Vector ids

A vector's id is `J.<group>[.<n>]`. The group is the vector's topic, for
example J.7 explicit typing and header parameters, J.10 delegation depth (I2),
J.19 the §4.5 subsumption table, and J.26 the leaf `check` predicates; the
generated document lists every group. `cbor_twin`, where it is set, names the
vector `A.x` in Tenuo's CBOR suite,
[`docs/spec/test-vectors.md`](../../docs/spec/test-vectors.md), that encodes the
same scenario with the same key seeds and timestamps. Only some vectors have a
twin (the generated document gives the count), and group numbers otherwise have
no relation to the CBOR suite's section numbers: J.15 is `all` subsumption,
A.15 an issuer constraint violation.

## Checking an implementation

Record your verifier's verdict for each vector id in a JSON file, then run
`python3 ietf/vectors/compare_results.py results.json`. [`INTEROP.md`](INTEROP.md)
describes the inputs, the results format, and how to report what you find.

## Regenerate

```bash
python3 -m pip install cryptography   # only dependency
python3 ietf/vectors/gen_vectors.py
```

## Validate

`scripts/validate_aat_vectors.sh` regenerates into a temporary directory and
diffs against the committed files, the same contract as
`scripts/validate_test_vectors.sh` for the CBOR vectors. It also runs the
mutation check below.

## What the suite pins

Every DENY vector differs from a valid presentation by one fault, and every
check in the §8 algorithm that can be the only fault in a presentation has a
vector that depends on it. `python3 ietf/vectors/gen_vectors.py
--mutation-check` enforces this: it disables each check of the generator's
verifier in turn (each lettered step and sub-step, each §3.4 well-formedness
rule, each `check` predicate and §4.5 subsumption rule, and the empty-map and
entry-type normalizations) and fails unless some vector changes verdict. A
few checks can never be the only fault, because another check always
fails with them; `UNREACHABLE` in the generator lists them with the reason, and
the generated document repeats the list. Steps 4e, 4f and 5 are among them.
`--fault-chains` prints, for every DENY vector, each check that fails once the
earlier ones are disabled.

The suite covers happy-path chains (single token, three levels, prefix
presentation, a chain at MAX_DELEGATION_DEPTH), each attenuation invariant I1
through I6, explicit typing and the other header rules on root, derived and PoP
tokens, every root and derived claim check, `authorization_details` entries of
other types and tokens without exactly one AAT entry, closed-world leaf checks and every
`check` predicate including range inclusivity and set semantics, the valid pairs
of the §4.5 table and a set of invalid ones, optional and unnamed arguments,
constraint well-formedness and depth, number admissibility, chain and PoP
audience, enforcement-point nonce, stateful PoP replay tracking at step 7i,
size limits, and duplicate members. Some PERMIT vectors catch over-strict
verifiers: unknown header parameters and claims, a header `jwk`, payloads that
are not JCS, same-key derivation, an `aud` array, and boundary values.

## Conventions

- AAT and PoP payloads are JCS-canonical except where a vector deliberately
  carries other bytes: an inadmissible number, number syntax that JCS would
  rewrite, duplicate members, or a non-canonical layout. Each token has a
  `payload_jcs_canonical` flag and an exact `payload_json` string. A verifier
  must verify the presented bytes and never re-canonicalize.
- Suite-level `params` apply to every vector, at the draft's recommended size
  limits (MAX_TOKEN_SIZE 65536, MAX_CHAIN_SIZE 262144). A vector's own `params`
  override them; J.23.2 and J.23.3 use smaller limits so that size is their only
  fault.
- Number admissibility (§3.4) is covered by `J.8.7`-`J.8.14`, and the rule that
  NumericDates, `del_depth` and `del_max_depth` have no fraction or exponent
  part (§3.2) by vectors such as `J.21.16` (`3.0`) and `J.24.5` (`2e0`). A
  harness must read each `args_json` and `payload_json` with a parser that
  keeps a number's exact value and whether it was written with a fraction or
  exponent. Ordinary JavaScript `JSON.parse` keeps neither: it cannot preserve
  `9007199254740993` or tell `1.0` from `1`. The parsed `args` and `payload`
  fields are conveniences only.
- No non-ASCII strings appear anywhere. Unicode tool-name matching needs its
  own vector set.
- Stateful replay vectors include the accepted PoP `jti` set before and after
  verification. Step 7i records a `jti` only after every earlier check passes.
- These vectors follow the -02 text. Tokens use `alg` `Ed25519` (RFC 9864)
  rather than -01's `EdDSA`, so an unmodified -01 verifier rejects nearly
  every vector; Appendix F of the draft lists the other verdict changes.
