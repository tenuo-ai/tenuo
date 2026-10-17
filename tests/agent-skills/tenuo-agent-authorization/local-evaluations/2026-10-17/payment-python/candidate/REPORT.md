# Payment authorization retrofit

Implemented and validated in this isolated project only. No real payment provider, external payment effect, committed key, commit, push, or delegation to other agents was used.

## Guarantee and scope

`PaymentClient.transfer` is the effect boundary. Its only fake payment effect (appending to its owned invocation record) runs after the configured Tenuo `Authorizer.check_chain` accepts the complete root-to-leaf chain, issuer trust, holder proof, current-time validity, `payment.transfer`, and the exact recipient and amount used by the effect. The verifier accepts public transport bytes, not signing keys, and trusts only the public issuer configured in its constructor. An unconfigured client fails closed. Configuration/construction is a trusted startup operation, never a request field. `execute_transfer(..., service=...)` is a convenience for trusted application assembly; its service argument must never be exposed as client-controlled transport data.

The original defining-module routes remain protected: direct construction, `payment_service.client.PaymentClient.transfer`, the module singleton, and `payment_service.client.execute_transfer` cannot send without authorization. Underscores alone are not the protection: authorization runs in the original effecting method. The invocation record is returned as a copy.

`issue_transfer_authority` is an application issuance API intended for the external issuer. It accepts an issuer-owned signing key and a holder PUBLIC key; grants exactly one recipient and an inclusive amount range 1..max_amount; permits TTL 1..300 seconds (default 60); and returns a complete public chain with a terminal holder-bound leaf. `present_transfer` executes at the caller, signs the final capability and arguments using the holder's key, and returns `Presentation(chain, signature)`. The verifier neither receives nor manufactures private-key proof. No application logging was added; presentation repr hides public authority/signature. No private keys are serialized into request data.

Amounts are positive Python integers bounded at 2**53-1, excluding booleans, floats, strings, zero, negatives, and larger integers. This preserves exact numeric meaning across authorization and execution. Recipient identifiers are exact strings without alternate normalization. Unknown transfer arguments cannot enter the method signature. No optional-warrant, development-trust, or observation mode is enabled.

Evidenced label: **development loop**, with **in-process enforcement**. There are usable application issuer and caller entrypoints, and their complete flow is tested. Tests generate ephemeral separate issuer/holder keys; this repository does not establish an externally operated issuer, production key ownership, or deployment isolation. It therefore does not evidence a production boundary.

Residual risks: Python callers with arbitrary execution in the verifier process can alter code/configuration or private state; isolation is operationally required before real payments. Production must provision the issuer public key independently, isolate issuer/holder secrets, and secure transport and clocks. `service=` and constructors are trusted assembly APIs. There is no atomic replay prevention, idempotency, immediate revocation-state feed, human approval, signed receipt collection, or transactional execution evidence. A repeated accepted presentation may cause repeated effects within its validity window. TTL and terminal delegation do not supply those properties. The fake record proves local invocation, not real payment settlement. The tests cover this payment method and its original routes, not unrelated application effects. Error causes are available for trusted diagnostics and should not be serialized to external callers.

## Measured behavior

Final suite: **19 passed in 2.15s**. Every denial test asserts the isolated effect record remains empty.

| Case | Observed effects |
| --- | ---: |
| Allowed application-issued terminal authority, merchant, 200, ceiling 500 | 1 |
| Valid narrower child (250 ceiling) under root-only trust | 1 |
| Missing authority | 0 |
| Untrusted issuer | 0 |
| Wrong holder proof | 0 |
| Expired authority (real clock, zero configured expiry tolerance) | 0 |
| Wrong capability (`payment.refund`) | 0 |
| Wrong recipient | 0 |
| Amount 501 against ceiling 500 | 0 |
| Missing parent chain | 0 |
| Signed child widened to ceiling 1000 under parent ceiling 500 | 0 |
| Original module/class/singleton/function bypass attempts | 0 |
| Malformed authority and modified signed arguments | 0 |
| Six invalid/lossy amount representations | 0 |

The wider-child test first has a positive narrower-child control. It modifies only the child's range maximum, correctly re-signs with the parent holder key, validates that issuer signature through the installed package, and submits the complete chain with correct worker proof. The concrete amount 200 is within both policies, so rejection proves envelope attenuation enforcement. Observed rejection: `Monotonicity violation: range expanded: child max (1000) exceeds parent max (500)`. Untrusted and missing-chain cases report `Root warrant issuer is not trusted`; other denial tests check corresponding capability, argument, expiry, or proof reasons.

Visible demonstration from the executed suite:

```text
Allowed payment.transfer(recipient=merchant, amount=200, ceiling=500): effects=1
Denied payment.transfer(recipient=merchant, amount=501, ceiling=500): effects=0 (asserted)
19 passed in 2.15s
```

## Resolved runtime and API evidence

- Python 3.12.11, Clang 17.0.0; tenuo 0.3.2; pytest 9.1.1; mypy 2.4.0.
- Installation is the project `.venv`, installed by `uv`; distribution has no `direct_url.json` (not reported as an editable checkout).
- Imported Python package: `.venv/lib/python3.12/site-packages/tenuo/__init__.py`.
- Imported native artifact: `.venv/lib/python3.12/site-packages/tenuo_core/tenuo_core.abi3.so`.
- Native SHA256: `cdab4164312a1a59f0f4978f9cc3c600b3dc575b39728a14656219873e3ce379`.
- Read the resolved wheel's README embedded in `tenuo-0.3.2.dist-info/METADATA`, exports, Python builder wrappers, native method signatures/docstrings, warrant extensions, and verifier dispatch. The wheel's `_stubs/__init__.py` is only a stub placeholder; native signatures and behavior supply the actual declarations here.
- Inspected installed files: `tenuo/{__init__.py,core.py,builder.py,_builder.py,bound_warrant.py,warrant_ext.py,mcp/server.py,_stubs/__init__.py}`; searched `keys.py`, `testing.py`, `receipts.py`, `approval.py`, and `cp_approval.py` for relevant APIs. No framework adapter is used.
- Installed native docstrings specify `check_chain(chain, tool, args, signature, ..., as_of=None)` with root-to-leaf ordering, and `Warrant.sign(keypair, tool, args, timestamp)`. The receiving API never exposes `as_of`.
- For the adversarial test only, native artifact strings and a signature equivalence probe established the released domain preimage `b"tenuo-warrant-v1\x01" + payload_bytes`. The test itself checks this equivalence and valid re-signing. Application code uses only normal SDK issuance/signing APIs.
- Skill horizon dated 2026-10-17 was consulted as hazard information. Live inventory refresh/merged-main verification was not performed; remote immutable source attempts failed (web cache miss and network DNS unavailable). No pending/main-only APIs were adopted, and no live-horizon compatibility claim is made.

## Commands and validation results

All commands ran with the project as cwd and its `.venv` runtime where applicable.

```text
.venv/bin/python .claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .
.venv/bin/pytest -q -s
.venv/bin/pytest -q -s --tb=short
.venv/bin/mypy payment_service --follow-imports=silent
.venv/bin/python -m compileall -q payment_service tests
git diff --stat
git status --short
```

The inventory is heuristic and mostly found skill self-references; direct source inspection established the actual payment routes. Initial validation found native attenuation setters return `None` rather than supporting fluent chaining (3 failures and 16 fixture errors). Setters were corrected to separate mutation calls. The subsequent run had 16 passing tests and 3 failures solely in reason-substring assertions; actual receiving denials and zero-effect checks succeeded. Those assertions were corrected to the observed `not trusted` and `range expanded` messages. The final rerun passed all 19 tests. This was one implementation with corrections within its validation pass, without an alternative integration or dependency upgrade.

Mypy: `Success: no issues found in 4 source files`. This is application checking with silent imported dependencies; the native wheel does not provide full static type declarations, so runtime tests are the primary native API evidence. Compileall completed with exit 0. Test invocation and checks were separate commands in a shell; individual outputs, rather than a shell's last exit status, were inspected.

Executed scripts, exactly:

1. `.claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py` (once).
2. `pytest` console script (three invocations: initial, corrected-builder run, final).
3. `mypy` console script (two invocations: initial and final).
4. Python standard-library `compileall` module (two invocations).
5. Inline Python probes (no saved script): distribution/runtime file inventory; native signatures/docstrings (initial partial probe stopped at a builtin signature without metadata); full native declaration enumeration; attenuation-builder declaration/wire probe; native export enumeration; signature-domain trials; failed urllib immutable-tag fetch; signature-domain equivalence search; source correction scripts (two); final runtime/version/native hash probe; cleanup of generated bytecode.

Other executed command tools: `pwd`, `rg` / `rg --files`, `cat`, `ls`, `sed`, `strings`, `head`, and read-only `git diff` / `git status`. Writes used shell here-documents and inline Python. A web open attempted `https://raw.githubusercontent.com/tenuo-ai/tenuo/v0.3.2/tenuo-core/src/warrant/mod.rs` and returned a cache miss; urllib attempted matching-tag `tenuo-core/src/warrant.rs` and failed DNS. No remote source was read or saved.

## Exact skill files read

All paths are relative to the project:

- `.claude/skills/tenuo-agent-authorization/SKILL.md`
- `.claude/skills/tenuo-agent-authorization/references/python.md`
- `.claude/skills/tenuo-agent-authorization/references/native-tools.md`
- `.claude/skills/tenuo-agent-authorization/references/trust-levels.md`
- `.claude/skills/tenuo-agent-authorization/references/unreleased.md`
- `.claude/skills/tenuo-agent-authorization/references/framework-status.md`
- `.claude/skills/tenuo-agent-authorization/references/common-footguns.md`
- `.claude/skills/tenuo-agent-authorization/references/security-model.md`

The inventory helper also scanned matching text in skill `framework-status.json`, `unreleased.json`, and its own/other inventory script sources; those were heuristic search hits, not separately opened reference instructions. The helper script above was executed, not separately opened for reading.
