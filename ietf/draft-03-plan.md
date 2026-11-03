# Planned changes for -03

Changes planned for draft-niyikiza-oauth-attenuating-agent-tokens-03, and
where each was raised. An item is checked off when it lands in
[the -03 source](draft-niyikiza-oauth-attenuating-agent-tokens-03.md) and
its change log. C and B numbers refer to Section 6 of
[draft-davliatshin-oauth-attenuation-chains-report-00](https://datatracker.ietf.org/doc/draft-davliatshin-oauth-attenuation-chains-report/).

## Text

- [ ] Duplicate members in the JOSE header (C1): steps 3a, 4a and 7a
      apply the same duplicate-name rule as the claims.
      [#1042](https://github.com/tenuo-ai/tenuo/issues/1042)
- [ ] JSON nesting depth (C2): relate the nesting a parser must accept to
      MAX_CONSTRAINT_DEPTH. At depth 32, J.8.15 nests 68 levels.
      [#1043](https://github.com/tenuo-ai/tenuo/issues/1043)
- [ ] Step 2c (C3): which jti is read when it repeats, and whether
      invalid JSON fails there. No verdict depends on it.
- [ ] typ comparison (C4): whether case variants and the `application/`
      prefix are accepted at 3a and 7a.
- [ ] aat_aud (C5): a single StringOrURI. The reference to RFC 7519 is
      for its meaning, not its form.
      [#1044](https://github.com/tenuo-ai/tenuo/issues/1044)
- [ ] Trust anchors that share a key (C6): a root passes 3k when its iss
      is an issuer configured for the key that verified its signature.
- [ ] Magnitude of NumericDate and depth values (C7).
- [ ] Invalid cnf.jwk (C8): a well-formed public key for a signature
      algorithm, under its kty's rules (RFC 8037 for OKP).
- [ ] Duplicate check when a binding has already parsed the arguments
      (C9).
- [ ] Root iss (C10): an absolute-URI, as in RFC 3986.
- [ ] Empty ranges (B4): whether equal bounds with an exclusive side are
      well-formed.
- [ ] Thumbprint URI comparison (B12): step 4c compares the strings
      exactly.
- [ ] sub (B15): ignored, like any other unrecognized claim.
- [ ] Implementation Status: list the aat verifier and cite the
      implementation report; update the Mission-Bound Authorization
      entry.

Considered, with no change planned: B9 (overlapping checks stay) and B18
(par_hash and aat_hash cover the signing input).

## Test vectors

Batched into one suite update, since each change moves the suite's
SHA-256.

- [ ] J.24.10: an expected step consistent with its description (C8).
- [ ] A JOSE header with a repeated typ (C1).
- [ ] An array aat_aud that names the enforcement point (C5).
- [ ] One key under two issuers (C6): a third suite anchor,
      `https://auth.example.net` with the control_plane key, and a root
      under that issuer. gen_vectors.py accepts any issuer configured for
      the verifying key.
- [ ] One issuer with two keys: a second anchor for
      `https://auth.example.com` with a new key, and a root signed by it.
- [ ] A del_max_depth lowered below the root's: a chain whose
      (del_depth, del_max_depth) runs (0, 8), (1, 2), (2, 2), (3, 2),
      denied at 4e.

## Alongside -03

- [ ] Constraint comparison with
      [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/)
      and
      [draft-hulea-wimse-agent-mandate](https://datatracker.ietf.org/doc/draft-hulea-wimse-agent-mandate/):
      for each constraint type, the narrowing rule in each draft, and a
      shared vector for each difference. Before IETF 127.
