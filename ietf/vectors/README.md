# AAT JWS test vectors

Byte-exact test vectors for the JWS profile of
`draft-niyikiza-oauth-attenuating-agent-tokens` (-02 reading). They are the
JWS twins of the CBOR vectors in [`docs/spec/test-vectors.md`](../../docs/spec/test-vectors.md):
same key seeds, same timestamps, matching scenario ids.

| File | Purpose |
|---|---|
| `gen_vectors.py` | Generator. Builds every vector and re-verifies it with an independent §7 implementation before writing. |
| `aat-jws-vectors.json` | Machine-readable suite: 67 vectors with expected verdict and cited §7 step. |
| `aat-jws-vectors.md` | Human-readable rendering of the same suite. |

Both output files are generated. Do not edit them by hand; change the generator
and regenerate.

## Regenerate

```bash
python3 -m pip install cryptography   # only dependency
python3 ietf/vectors/gen_vectors.py
```

## Validate

`scripts/validate_aat_vectors.sh` regenerates into a temporary directory and
diffs against the committed files, the same contract as
`scripts/validate_test_vectors.sh` for the CBOR vectors.

## What the suite pins

Happy-path chains (single token, three levels, prefix presentation), each
attenuation invariant I1 through I6, closed-world leaf checks, explicit JWT
typing, required PoP audience, composite `all`/`any` subsumption including
clause reuse, the remaining core constraint types, and the structural root
checks of §7 steps 3c, 3d, 3f, 3h, 3l.

## Conventions worth knowing

- AAT payloads are JCS-canonical so the signing input is reproducible; a
  verifier must verify the presented bytes and never re-canonicalize.
- No floats and no non-ASCII strings appear anywhere. Numeric canonicalization
  and Unicode tool-name matching need their own vector sets once the -02 text
  on those points is final.
- Draft-01 implementations will disagree on `typ`, required `aat_aud`, and the
  two `all` clause-reuse cases (`J.15.3`, `J.15.4`). Those encode -02 changes.
