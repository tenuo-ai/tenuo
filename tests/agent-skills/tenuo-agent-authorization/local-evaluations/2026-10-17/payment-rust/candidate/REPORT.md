# Payment authorization retrofit

Authorization result: **development loop**. In-process guardrail: **yes**. No real payments or external effects were used.

## Result and precise guarantee

Calls reaching `PaymentService::transfer` or `execute_transfer` execute the service-owned fake payment effect only after the independently configured Tenuo verifier accepts the encoded warrant chain, holder proof, `payment.transfer` capability, exact recipient, and amount constraints. The verifier receives public presentation artifacts, never an issuer or holder private key. The service constructor trusts exactly the issuer public key supplied by its trusted operator; requests cannot select roots, clocks or enforcement modes.

`issue_transfer` is an issuer-side API, `present` is a holder-side API, and `examples/payment.rs` demonstrates their complete usable flow. Keys are ephemeral and co-located only in the development example and tests. No private keys are serialized into requests or logged. In deployment, run issuance under the authority owner's control and keep it outside the untrusted caller and effect-service process.

The private `PaymentClient` is owned exclusively by the service. Both old unguarded entrypoints are closed: external code cannot access the original defining-module `PaymentClient::transfer`, and the original three-argument `execute_transfer` signature no longer compiles. Executable compile-fail doctests attempt both original routes.

Amount is integer minor currency units, restricted to 1..=1,000,000 before checked conversion to Tenuo's i64 argument representation. All accepted amounts and Range limits are exactly representable in f64. Recipient is a nonempty exact string of at most 256 bytes. Verification and effect use the same owned request values, without asynchronous gaps or caller callbacks. The caller cannot choose the capability executed by the service. Root authority expires within 300 seconds; explicit TTL-only verification enforces that maximum lifetime. One delegation is supported, with full root-first chain and root-only trust; the tested narrower child has a 60-second TTL and is terminal at depth 1. Encoded warrants are decoded at the boundary, with at most two warrants and 16 KiB per warrant.

## Measured behavior

`cargo test --locked --offline`: **10 behavioral tests and 2 compile-fail doctests passed**, zero failures. Each denial case checks the effect record remains empty.

| Case | Outcome | Effects |
| --- | --- | --- |
| Merchant, amount 200 under amount<=500 | Allowed | 1 |
| Missing authority | MissingAuthority | 0 |
| Untrusted issuer | UntrustedRoot | 0 |
| Wrong holder signing proof | SignatureInvalid (this release's actual code) | 0 |
| Correctly signed expired warrant | WarrantExpired | 0 |
| payment.refund warrant used for transfer | ToolNotAuthorized | 0 |
| Recipient attacker | ConstraintViolation | 0 |
| Amount 501 | ConstraintViolation | 0 |
| Valid narrower child, merchant amount<=250 | Allowed with root-only trust | 1 |
| Same child widened to amount<=600 and correctly re-signed by delegator | CapabilityExpansion | 0 |
| Delegated leaf missing parent | Rejected | 0 |
| Malformed encoded warrant | Rejected | 0 |
| Zero, 1,000,001, 2^53+1, u64::MAX amounts | InvalidArguments | 0 |
| Original raw client and function signatures | Compilation fails | Inaccessible |

The delegation test first establishes a successful child with the correct child holder, then changes only its amount envelope and re-signs it with the valid parent holder. This exercises receiving-boundary attenuation rather than a friendly builder refusal.

Actual `cargo run --locked --offline --example payment` output:

```text
Task warrant: payment.transfer(recipient=merchant, amount<=500), TTL<=300s
Allowed amount=200: effect count=1
Denied amount=501: Err(Denied(Some(ConstraintViolation))); new effects=0
```

`cargo check --locked --offline --all-targets` and `cargo fmt --check` passed.

## Runtime and source evidence

- rustc 1.99.0 (b940084d7 2026-09-28)
- cargo 1.99.0 (5f94df478 2026-08-27)
- Python 3.14.5 (inventory and file editing only)
- Package payment-service-eval 0.0.1, Rust edition 2021.
- Cargo.lock resolves crates.io `tenuo` **0.3.2**, checksum `bc8d5469d722e7c7a3998191da4770e5ae488ed687f3e3c4e58ff6ca723fe745`.
- Actual package source inspected at `/Users/danieljoseph/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tenuo-0.3.2/`.
- Enabled features confirmed by `cargo tree`: sdk, default, control-plane, data-plane. No dependency or lockfile changes.
- Inspected that package's README.md, examples/sdk_mcp_demo.rs, and declarations/implementation in src/{lib.rs,warrant.rs,payload.rs,crypto.rs,wire.rs,constraints.rs,error.rs,sdk/guard.rs,sdk/authority.rs,sdk/call.rs,sdk/tenuo.rs,sdk/decision.rs}; targeted security-test searches confirmed installed behavior. No APIs from pending branches were used.
- The bundled horizon snapshot is dated 2026-10-17; its open-PR descriptions are hazard context, not installed APIs. No independent live horizon refresh was performed.

## Commands and validation history

Read/search commands used `pwd`, `rg --files`, `rg -n`, `cat`, `head`, `sed`, `ls -la`, `printenv CARGO_HOME CARGO_TARGET_DIR`, and `git diff --stat`, scoped to this project and the exact resolved registry package. File writes used shell heredocs, `mkdir -p examples`, and inline Python editing of src/lib.rs. No other project was inspected; no delegation, commit or push was performed.

Runtime/resolution/validation commands executed:

```text
rustc --version
cargo --version
cargo metadata --locked --format-version 1 --no-deps
cargo metadata --locked --offline --format-version 1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print([(p["manifest_path"],p["version"]) for p in d["packages"] if p["name"]=="tenuo"])'
python3 .claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .
cargo test --locked --offline
cargo fmt
cargo check --locked --offline --all-targets
cargo run --locked --offline --example payment
cargo fmt --check
python3 --version
cargo tree --locked --offline -e features -i tenuo
```

Baseline: two tests passed. Full offline metadata failed because it requested uncached target-specific `cc v1.8.0`; its JSON parsing consequently failed. Actual host tests/checks needed no downloads and succeeded. Within the single implementation/validation pass, initial compilation identified that `terminal()` belongs to a different builder; installed AttenuationBuilder uses `max_depth(1)` here. The next test run passed eight tests and identified two differing error-code expectations; assertions were corrected to installed `SignatureInvalid` and `CapabilityExpansion`. Final test run passed all 12 checks. Formatting ran after edits and the final format check passed.

Exact skill files read (relative to this project):

```text
.claude/skills/tenuo-agent-authorization/SKILL.md
.claude/skills/tenuo-agent-authorization/references/rust.md
.claude/skills/tenuo-agent-authorization/references/native-tools.md
.claude/skills/tenuo-agent-authorization/references/trust-levels.md
.claude/skills/tenuo-agent-authorization/references/common-footguns.md
.claude/skills/tenuo-agent-authorization/references/security-model.md
.claude/skills/tenuo-agent-authorization/references/unreleased.md
.claude/skills/tenuo-agent-authorization/references/framework-status.md
```

Exact skill scripts executed: only `.claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .` via python3. The scanner mostly found its bundled skill metadata; source inspection established that this tiny service has no framework dispatcher or network listener.

## Residual risks and deployment dependencies

This is a library with a recording fake, not a deployed independent payment service. Production isolation, issuer provisioning, holder secret custody, authenticated transport, and real payment credentials are not established. A hostile process able to replace this code or access payment credentials is outside this boundary. Put the verifier and effect adapter in a separately trusted service before claiming a production boundary.

PoP does not provide nonce consumption or idempotency: repeated valid requests can execute repeated effects within accepted time windows. No exactly-once, replay-prevention, immediate revocation, human approval, receipt, execution-attestation, or human-intent guarantee is claimed. TTL-only mode means authority remains usable until expiry even after central revocation. The warrant authorizes each transfer, not cumulative spending. Local clock integrity and the released crate's cryptography, parsing, chain and numeric constraint implementations remain trusted. No observation, shadow, optional-authority or development bypass mode exists in the effect API. The demo's development label describes co-located ephemeral keys, not weakened verification.
