# Payment authorization retrofit

The fake payment effect now belongs exclusively to `createPaymentService(configuredIssuerPublicKey).executeTransfer(recipient, amount, presentation)`. The former `PaymentClient`, singleton `client`, and free `executeTransfer` implementation were removed from their defining module. All transfer records are private closure state; callers receive frozen copies. Construction is a trusted composition operation, not request configuration.

## Precise guarantee

Calls reaching this service instance append a fake payment record only after the installed Tenuo verifier accepts the configured issuer root, full warrant chain, holder proof, expiry, capability `payment.transfer`, and recipient/amount constraints. The host ceiling is recipient exactly `merchant`, integer minor-unit amounts 1–500 inclusive, intersected with issued authority. Final arguments are snapshotted by the verifier and its returned values are used for the effect. No numeric coercion, rounding, or currency conversion occurs. Missing authority fails closed. The verifier receives public warrant/proof transport only, never holder or issuer signing keys, and does not manufacture caller proof. Application code contains no logging.

Fixtures issue 120-second parent authority for merchant / amount 1–300, bound to a separate holder; a delegated terminal child lasts at most 60 seconds and caps amount at 200. Only the original root is trusted at the receiver. Complete chains are transported using the installed SDK's presentation format.

Authorization integration label: **incomplete integration**, under the skill's deployment criteria: issuer-to-holder-to-verifier behavior is demonstrated with tests, but minting exists only in fixtures; this repository has no deployed legitimate issuance service or production key management. Test-only minting cannot establish a development loop or production boundary. The application verifier API itself is usable with externally issued presentations. In-process guardrail: yes if this library runs in the agent's own process. It is an independently configured verifier, not evidence of a separately operated production process.

## Runtime and resolved artifact

- Node `v24.10.0`; npm `11.6.0`; TypeScript `5.9.3`; Vitest `3.2.4`; `@types/node` `24.19.2`.
- Installed/locked `@tenuo/core@0.3.2-beta.0`; registry tarball `https://registry.npmjs.org/@tenuo/core/-/core-0.3.2-beta.0.tgz`.
- Lock integrity: `sha512-Cyq1YxxI417hREikPxCcPPpdiHvWhEXLc3/ahpA7jb89IelULbQfYdUinQEOY8CxnprIFANqg3xuZRBtKB5eUQ==`.
- Import resolution: `/private/tmp/tenuo-local-agent-evals/payment-typescript/node_modules/@tenuo/core/dist/index.js`.
- Runtime dispatch inspected: `dist/client.js` -> `dist/mcp.js` (`verifyPresented`, argument snapshot, `authorizePresented`, decision before return) -> `dist/wasm.js` -> `dist/generated/tenuo_wasm.js` + `tenuo_wasm_bg.wasm`.
- Measured WASM SHA-256 `071de0080d616e5519841930f0579e5234a93a9f29724595609744d43b7e9d4a` matches packaged build-info hash. Build-info records source commit `7f27c7d4782f8f19ec15313e09ab95883a1da811`, `sourceClean:false`, `wasmMatchesCommit:false`; reproducible source provenance is therefore not established. This report covers the actual installed artifact.
- Package README, exports, API/constraint/session/identity/runtime/error/client declarations and generated WASM declarations were inspected. No dependency upgrade, source checkout, network lookup, or unreleased API adoption occurred. Horizon reference timestamp was 2026-10-17T14:19:09.763226+00:00; its historical main/PR summaries were treated only as hazards, not available APIs. Live main was not independently fetched.

## Measured validation

Final `npm test`: **17 passed**, one test file, 51 ms test time / 358 ms run. Final `npm run typecheck`: **passed**.

| Scenario | Result | Fake effects |
|---|---|---:|
| Holder-bound allowed merchant / 200 presentation | allowed | 1 |
| Missing authority | missing-authority error | 0 |
| Untrusted issuer | TENUO_UNTRUSTED_ROOT | 0 |
| Wrong holder proof | TENUO_INVALID_POP | 0 |
| Expired warrant, fresh holder proof | TENUO_WARRANT_EXPIRED | 0 |
| Wrong capability | TENUO_TOOL_NOT_AUTHORIZED | 0 |
| Recipient attacker | TENUO_CONSTRAINT_VIOLATION | 0 |
| Amount 301 under parent max 300 | TENUO_CONSTRAINT_VIOLATION | 0 |
| Trusted broader warrant beyond host ceiling | TENUO_CONSTRAINT_VIOLATION | 0 |
| Zero, negative, fractional, NaN, infinity, unsafe integer | invalid argument | 0 each |
| Valid terminal child max 200 with full chain and root-only trust | allowed | 1 |
| Same child widened to 400 and correctly re-signed by parent holder | range-expanded denial | 0 |
| Delegated leaf without parent | TENUO_UNTRUSTED_ROOT | 0 |
| Original raw construction / singleton / free function | inaccessible, TypeError | 0 |

The wider-child test changes only the child's maximum and signature, verifies that signature with Node crypto, then sends the altered full chain to the receiving application boundary. It asserts the diagnostic `range expanded: child max (400) exceeds parent max (300)`. The installed package maps this to the surprising `TENUO_TOOL_NOT_AUTHORIZED`, so the test also checks the reason. The valid child is the positive control. Public `narrow` separately refuses widening.

Invalid policy tests use the bundled WASM `signMeta` test seam to bypass caller-side presentation preflight; all required rejection assertions run at the receiving service. The expiry test changes the process clock only within private test code; the application exposes no time override. Test fixtures require a nonempty root list even for a signer-only context.

The deliberately invalid `checks/original-bypass.ts` imports all three original symbols from `src/payment.js`. Running `node node_modules/typescript/bin/tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --skipLibCheck checks/original-bypass.ts` produces **three expected TS2305 errors** (compiler exit 2). The fixture is outside the normal `src` typecheck include. Runtime tests also attempt the original constructor and `.transfer` method at their original module.

Validation history within this implementation: initial test run had 14 fixture setup failures (empty roots), then 16/17 passed after correcting signer fixtures and test clock; the remaining assertion expected the wrong SDK error code for widening. Correcting that assertion to the measured code and checking the attenuation diagnostic yielded 17/17. Typecheck passed on both explicit invocations. No application authorization logic was relaxed to accommodate a test.

## Residual risks and operational dependencies

- No replay store, payment idempotency, transaction coordination, or exactly-once guarantee: a valid PoP can be replayed within its accepted window and repeat effects. The one-effect assertion describes one allowed invocation, not a one-use token.
- No immediate revocation, approval workflow, durable receipts, or evidence of a real downstream payment. TTL bounds exposure but is not revocation.
- A production host must independently provision issuer roots, operate issuance outside the agent, protect holder/issuer keys, keep a trustworthy clock, isolate the effect service, and prevent access to alternate real payment credentials/routes. Arbitrary execution in the trusted service process is outside this library's protection.
- All effects here are isolated in-memory records. No merchant API, network payment, or live credentials were used.
- The test-only adversarial CBOR mutation is pinned to this installed wire encoding, with assertions for encoding position and signature validity. It is not an application transport implementation.
- Private keys are absent from application logs and request data. One exploratory test-only `exportWire()` probe printed a generated ephemeral holder seed to tool output; that seed is not stored in code, requests, application logs, or this report and is never used beyond the discarded probe. Production diagnostics must never serialize that internal export.

## Exact skill files read and scripts executed

Skill source files read (all relative to this project):

1. `.claude/skills/tenuo-agent-authorization/SKILL.md`
2. `.claude/skills/tenuo-agent-authorization/references/typescript.md`
3. `.claude/skills/tenuo-agent-authorization/references/trust-levels.md`
4. `.claude/skills/tenuo-agent-authorization/references/native-tools.md`
5. `.claude/skills/tenuo-agent-authorization/references/common-footguns.md`
6. `.claude/skills/tenuo-agent-authorization/references/unreleased.md` (overview and applicable hazard inventory; large combined output was truncated)
7. `.claude/skills/tenuo-agent-authorization/references/framework-status.md` (historical overview; combined output was truncated; no framework adapter selected)
8. `.claude/skills/tenuo-agent-authorization/references/security-model.md`

Skill script executed once: `python3 .claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .`. Its heuristic results included bundled skill inventory false positives; manually confirmed application effects and original bypasses in `src/payment.ts`. No other skill script was executed.

Other scripts executed:

- Nine `node --input-type=module` inline API probes, in order: (1) export/decode probe with incorrect positional range arguments, failed configuration; (2) export/decode with options range and empty builder config, succeeded; (3) signature message candidates and builder config without TTL; (4) builder tools shape / lowercase range; (5) nested range variants; (6) direct min/max builder fields; (7) capitalized Range/Exact builder syntax; (8) wider delegated builder, rejected range expansion; (9) signature domain candidates, confirmed `tenuo-warrant-v1` + byte 1 + payload. These are disposable inline probes, not application code or stored scripts.
- Two `python3` inline edit scripts adjusting test-only fixture setup/clock and expected widening error diagnostics.
- `npm test` three times: initial fixture failures, 16/17, final 17/17.
- `npm run typecheck` twice: passed both times. The first `npm test && npm run typecheck` invocation skipped its chained typecheck due to test failure.
- The deliberate negative TypeScript compiler command above, once, expected three TS2305 diagnostics.

Additional read-only commands/probes: `pwd`; `rg --files`; `cat` and `sed` of the enumerated skill and installed artifacts and project manifests/source; `rg` searches of package dispatch/declarations, lock metadata, and horizon references; `ls -la`; `node --version`; `npm --version`; `node -p "require.resolve('@tenuo/core')"`; `npm ls --depth=0`; `strings` of the bundled WASM with `rg` filters; `shasum -a 256 node_modules/@tenuo/core/dist/generated/tenuo_wasm_bg.wasm`; `node -p "JSON.stringify(require('./package-lock.json').packages['node_modules/@tenuo/core'])"`; `git diff --stat`; `git status --short`. Shell heredocs wrote application/tests, the negative fixture, and this report. No other project was inspected; no delegation, commits, or pushes occurred.
