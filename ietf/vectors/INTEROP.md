# AAT JWS vector interop

Results of running the AAT JWS test vectors
([`../../tests/vectors/aat-jws-vectors.json`](../../tests/vectors/aat-jws-vectors.json))
against implementations of `draft-niyikiza-oauth-attenuating-agent-tokens`.
An implementation is listed here only with its maintainers' agreement.

## Running the suite

For each vector, verify `chain_compact` and `pop.compact` as Section 8
describes, for the invocation `tool` with the arguments in `args_json`, at the
time `now`. The suite-level `trust_anchors` and `params` apply to every vector;
a vector's own `params` and `policy` override them, and `replay_state.before`
is the accepted PoP `jti` set when a vector tracks replay. Read `args_json`
and each token's `payload_json` with a parser that keeps a number's exact
value; [`README.md`](README.md) lists the conventions.

Record each verdict by vector id, as a JSON object:

```json
{"J.1": "PERMIT", "J.2": {"verdict": "DENY", "step": "2c"}}
```

A vector your implementation does not support can be `"SKIP"`, with an
optional `"reason"`. An implementation with a different token format can
run the suite at the property level: express each scenario it can in its
own format, and record the rest as `"SKIP"` with a reason. Then compare:

```bash
python3 ietf/vectors/compare_results.py results.json
```

It prints the suite's SHA-256, so a report names the exact bytes it ran
against, then the count of agreements and every disagreement. Only verdicts
are compared: Section 8 permits some reordering, so a different failing step
is not a disagreement (`--steps` lists them).

## Reporting

Open an issue or a pull request with the comparison output, and say:

- the implementation's name, language, version, and license;
- whether we may list it here and in the draft's Implementation Status
  section.

Each disagreement is either a bug on one side or an ambiguity in the draft.
Please report both; ambiguities are fixed in the draft.

## Results

| Implementation | Language | Version | Suite SHA-256 | Agree | Skipped | Notes |
|---|---|---|---|---|---|---|
| `gen_vectors.py` self-check | Python | this repository | `b7a42e9dfdce7fbc…` | 229 / 229 | 0 | Generates the suite; its Section 8 verifier shares no code with Tenuo. |
| [VAID](https://github.com/solara-associates/vaid) (`vaid-mint`) | Rust | 0.11.0, Apache-2.0 | `b7a42e9dfdce7fbc…` | 22 / 229 | 207 | Property-level run in a different token format: VAID has no per-hop holder-key signing, JOSE headers, or constraint-predicate algebra, so most vectors testing those are `SKIP`, each with a per-scenario reason. 0 disagreements, 0 missing. [Harness](https://github.com/solara-associates/vaid/blob/254d7441e53df2d025311da73e81420c35b76959/crates/vaid-mint/examples/aat_interop_harness.rs), [results](https://github.com/solara-associates/vaid/blob/254d7441e53df2d025311da73e81420c35b76959/docs/aat-interop/s485-results.md). |
| [Mission-Bound Authorization reference architecture](https://github.com/mcguinness/mission-bound-authorization) (`mission-core`) | TypeScript | commit `020e7885`, BSD-2-Clause | `b7a42e9dfdce7fbc…` | 229 / 229 | 0 | Full run in the suite's token format: each vector's `presentation` goes through its Section 8 verifier, with no exclusions, in the project's CI. [Test](https://github.com/mcguinness/mission-bound-authorization/blob/020e78858199403903d5a873c7644523b965826a/src/packages/mission-core/test/aat-vectors.test.ts), [suite pin](https://github.com/mcguinness/mission-bound-authorization/blob/020e78858199403903d5a873c7644523b965826a/src/packages/mission-core/test/vectors/aat/README.md). |
