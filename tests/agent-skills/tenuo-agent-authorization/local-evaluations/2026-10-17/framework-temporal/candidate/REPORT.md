# Refund activity authorization report

Authorization result: **development loop**. In-process guardrail: **yes**.

Implemented Tenuo verification at `agent_app.refund_order`, the original effecting callable, immediately before retry controls and the fake refund record. `refund_security.RefundVerifier` owns an `Authorizer` configured with a public issuer root independently of invocation arguments. It never receives a private signing key or signs caller proof. `dev_authority` supplies a functional local issuer/holder path used by `run_refund`; its keys are ephemeral and remain outside workflow arguments/history.

## Scope and implementation

- Capability: `refund_order`; exact string order `"123"`; integer USD cents from 1 through 50,000 inclusive. No float/string/bool coercion. The receiver also enforces this ceiling independently of warrant scope and executes with the same values passed to verification.
- Issuer and holder are different keys. Issuance grants a 60-second warrant. A caller signs the final material arguments before starting the workflow. Only public base64 warrants and hex PoP signatures enter workflow/activity arguments. Verification uses the installed full `Authorizer.check_chain` path, with root signature/trust, holder proof, lifetime, capability and constraints. Clock tolerance is explicitly zero; PoP windows use installed defaults (30 seconds, 5 windows).
- Public authority travels unchanged through pause/resume and Temporal activity retries. Every attempt verifies before executing. Denials become non-retryable `RefundAuthorizationDenied` errors. Missing authority never triggers issuance at the receiver. `run_refund`'s omitted-authority convenience is explicitly the local caller issuance path; passing `authority=None` exercises missing transport.
- `framework_ctx` contains only tracing and the starter's synthetic pre-effect retry switch. These do not select refund order or amount and are excluded from capability arguments; no wildcard or unknown-material-argument relaxation was added.
- Delegated presentations carry a complete root-to-leaf chain, at most eight entries. Only the issuer root is trusted. Tests establish a narrower terminal child with a separate holder, missing-parent rejection, child-constraint rejection, SDK widening rejection, and receiver rejection of an unrelated holder-signed leaf presented as a child. Normal root issuance retains the SDK default delegation ceiling (max depth 64); delegation is not needed on the ordinary refund path.
- The original `agent_app.refund_order` callable remains guarded even when called directly. No alternate raw refund helper/client was introduced. The effect remains exclusively a fake in-memory record; no provider or payment requests were made.

## Actual demonstrations

These measurements come from the passing tests, not illustrative output:

```text
Task authority: refund_order(order_id="123", 1 <= amount_cents <= 50000)
Allowed: $200, retry -> attempts [1, 2], fake effect [("123", 20000)]
Allowed: $200, resume -> fake effect [("123", 20000)]
Allowed: $500, retry + resume -> attempts [1, 2], fake effect [("123", 50000)]
Denied: $500.01 and $4,900 -> zero fake effects
Denied: order "124" -> zero fake effects
Denied: missing authority through Temporal retry + resume -> zero fake effects
Denied: direct original handler without authority -> zero fake effects
Allowed: terminal child for <=$100, complete chain -> one $100 fake effect
Denied: same child without parent or at $100.01 -> zero fake effects
```

Other passing denials cover malformed warrant transport, altered proof, untrusted issuer, wrong holder, wrong capability, changed final amount, expired warrant, zero/negative/huge amounts and non-lossless input types. Each receiving-boundary denial checks the error category/reason and empty attempt/effect records. Temporal denial tests check terminal errors and zero effects through the actual workflow/activity dispatcher. Widening to 50,001 cents is rejected at child construction with `Monotonicity violation`; the receiving malformed-chain test separately checks `parent_hash` rejection, rather than claiming SDK construction failure proves receiver attenuation behavior.

## Runtime and source probes

- Python: 3.12.11, Clang 17.0.0; executable `/private/tmp/tenuo-local-agent-evals/framework-temporal/.venv/bin/python`.
- `tenuo` distribution: 0.3.2; imported source `/Users/danieljoseph/Claude/Tenuo/tenuo-skill-readiness/tenuo-python/tenuo/__init__.py`.
- Editable metadata: `file:///Users/danieljoseph/Claude/Tenuo/tenuo-skill-readiness/tenuo-python`, `editable=true`.
- `git rev-parse HEAD` in that checkout: `abe73aab4df50a7044ab8b0d560b061c2b57d650`, matching `SDK_SOURCE.json`. Requirements and lockfile were inspected; no SDK upgrade was made.
- Native extension: `/private/tmp/tenuo-local-agent-evals/framework-temporal/.venv/lib/python3.12/site-packages/tenuo_core/tenuo_core.abi3.so`.
- Native SHA-256: `b619ec542fd7497f3bfc690ffd4b025769809b071238ce263dfc189ad7385742`. This identifies the actual artifact; matching build provenance to the editable Git commit was not independently established.
- Temporal Python 1.34.0, pytest 9.1.1, pytest-asyncio 1.4.0.
- Live local server banner: Temporal CLI 1.9.1, Server 1.32.0, UI 2.54.1; in-memory persistence, localhost only.
- Inspected importable exports, signatures and docs for `Authorizer`, `authorize_one`, `check_chain`, `Warrant`, mint/attenuation builders, `sign`, `SigningKey`, `Range`, `Exact`. Confirmed actual proof and chain calls with native probes.
- Inspected the installed adapter's `tenuo/temporal/{__init__,_config,_headers,_interceptors}.py` and relevant lines in installed `examples/mcp_server.py`. The Temporal adapter's pending injected-argument/replay concerns informed the handler-level integration. No adapter hook is relied upon for enforcement. The provided horizon snapshot was dated 2026-10-17; it was read as hazard context, not imported API documentation. No remote horizon refresh was performed.

## Validation commands and results

All commands ran from this project, using `.venv/bin/python`.

1. `python .claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .`: completed; source inventory confirmed the single refund activity. The heuristic also scanned bundled skill metadata; those matches were not application routes.
2. `python -m pytest tests/test_app.py -q`: first sandboxed attempt failed both tests because local server process startup returned `Operation not permitted`. Repeating with permission for the local test server: **2 passed in 1.58s**.
3. `python -m pytest tests/test_authorization.py -q`: initial collection failed because `WorkflowFailureError` belongs to `temporalio.client`; corrected import. Next run: **19 passed, 4 failed**, exposing fixture assumptions (native denial wording, base64 history payloads, mutating attenuation builder returns). Corrected those tests.
4. `python -m pytest -q`: **22 passed, 3 failed**, exposing remaining fixture assumptions (SigningKey secret serialization API and exact trust/parent-hash denial reasons). Corrected assertions to installed APIs and actual denial categories.
5. Final `python -m pytest -q`, with local server permission: **25 passed in 4.49s**. This includes both unchanged starter tests and the added authorization cases.
6. `python -m compileall -q agent_app.py dev_authority.py refund_security.py tests`: **passed**. No configured static type checker exists in this starter; compilation is not a type-check claim.

This was one handler-level implementation and its validation pass; fixes during validation were to test API/fixture assumptions. No alternative SDK versions or implementations were tried.

## Files read and scripts executed

Exact skill files read (relative to this project):

- `.claude/skills/tenuo-agent-authorization/SKILL.md`
- `.claude/skills/tenuo-agent-authorization/references/python.md`
- `.claude/skills/tenuo-agent-authorization/references/native-tools.md`
- `.claude/skills/tenuo-agent-authorization/references/framework-status.md`
- `.claude/skills/tenuo-agent-authorization/references/unreleased.md`
- `.claude/skills/tenuo-agent-authorization/references/trust-levels.md`
- `.claude/skills/tenuo-agent-authorization/references/common-footguns.md`
- `.claude/skills/tenuo-agent-authorization/references/security-model.md`

Executed script files: the inventory script named above; `tests/test_app.py` and `tests/test_authorization.py` via pytest, importing the project modules and installed Temporal/Tenuo runtime. Additional inline Python scripts performed module/version/metadata/native-artifact hashing and API signature/builder probes, edited test fixtures, and ran native positive-control signing/verification and delegation probes. Shell heredocs created the three application files, added tests, and wrote this report. These probes used only ephemeral keys and fake/local resources. A misspelled `tenuo._tuenuo` probe failed with `ModuleNotFoundError`; the real native module was subsequently resolved and hashed. Attempts to inspect nonexistent SDK flat module paths and a callable signature on a property also failed harmlessly before the correct source/API was located. Shell inspection used `pwd`, `rg`, `cat`, `head`, `sed` and read-only `git rev-parse HEAD`; no external skill scripts, SDK tests, evaluation results/rubrics, or other starter projects were read or executed.

Changed/added files: `agent_app.py`, `dev_authority.py`, `refund_security.py`, `tests/test_authorization.py`, and this report. Existing starter tests and dependency files remain unchanged. No commit or push was performed.

## Remaining limits

This is a working cryptographic development loop, not a production boundary: the local issuer/holder keys and verifier share a mutable Python process. Arbitrary code in that process can replace configuration, access development keys or mutate the fake records. Production needs independently operated issuance and effect ownership, persistent roots/secure key management, and a deployment model isolating the verifier from the agent.

The $500 maximum is **per invocation**, not a cumulative order budget. Repeated valid requests can repeat the fake refund. PoP is not nonce consumption; no replay suppression, durable idempotency, exactly-once guarantee, revocation distribution, approvals or execution receipts were added. Retry testing covers the starter's failure before the effect; a failure after a real downstream mutation would need durable idempotency. Resume testing uses the existing local signal path within the 30-second workflow execution timeout; long suspension beyond the 60-second warrant lifetime fails closed and needs an explicit renewal design. Worker restart/history replay and long-running retries were not tested. The resume signal coordinates execution and does not itself grant refund authority.

Calls reaching the guarded refund activity execute the fake refund only after the configured verifier accepts the chain, holder proof, capability and final constrained arguments. This statement covers the named activity and demonstrated local paths, not arbitrary application actions or downstream payment completion.
