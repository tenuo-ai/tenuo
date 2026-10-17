# Refund authorization implementation

Authorization result: **development loop**. In-process guardrail: **yes**. This is an enforcing, signed-warrant integration for the local fake refund effect, not a production isolation boundary.

The original `Agent.input_guardrails` integration inspected initial user input, leaving later model-selected refunds unprotected. The replacement path is:

`development_session issuance → scripted Model → Runner / FunctionTool → holder presentation → RefundService.refund_order → Authorizer.check_chain → fake effect append`.

The service receives only root-first serialized warrants and a signature, never an issuer or holder private key. It verifies the complete chain against its constructor-provisioned root public key immediately before its sole effect. The original `agent_app.refund_order.on_invoke_tool` route and SDK `.__wrapped__` callable both reach enforcement; neither retains the old unguarded append. A caller constructing a new RefundService still must present authority accepted by that service.

The sole capability is `refund_order`, with `order_id=Exact("123")` and `amount_cents=Range(min=1,max=50000)`. An independent service ceiling enforces the same envelope even if a trusted issuer grants more. Amounts are integer USD cents, strictly positive and at most $500 per invocation; booleans, floats, string coercion and out-of-domain integers are rejected. This is a per-call limit, not a cumulative task budget. No additional currencies, destinations, accounts, hosted tools, handoffs, MCP or execution tools exist in this starter.

The application issuer creates a 300-second parent bound to a separate holder, which creates a 240-second terminal leaf. Both grants have the same bounded task envelope; delegation is used here to obtain a terminal execution leaf through the installed API. The runtime sends both parent and leaf and signs each final call. The service checks actual current time with zero expiration tolerance. The verifier never manufactures caller proof. Issuer key is not retained after demo setup; holder key is in trusted runtime context, outside model tool arguments. Missing, malformed, tampered, expired, untrusted, wrong-holder, wrong-capability and constraint-invalid requests fail closed. Unknown model arguments are rejected by explicit key-set validation; no observe or optional-warrant path is enabled.

## Runtime and API evidence

Inspected the actual local `.venv`, requirements and project manifest; no dependencies were upgraded. Runtime is CPython 3.12.11, Clang 17.0.0, executable `/private/tmp/tenuo-local-agent-evals/framework-openai/.venv/bin/python`. Dependencies resolve from `/private/tmp/tenuo-local-agent-evals/framework-openai/.venv/lib/python3.12/site-packages`:

| Distribution | Installed version |
| --- | --- |
| tenuo | 0.3.2 |
| openai-agents | 0.22.0 |
| openai | 3.33.0 |
| pytest | 9.1.1 |
| pytest-asyncio | 1.4.0 |

All five have no `direct_url.json`; there is no evidence of editable or git installation. No lockfile exists in this starter. Exact wheel publisher/source commit cannot be established from metadata; artifact hashes distinguish this runtime from other checkouts sharing a version. `scripts/runtime_probe.py` reports import paths, versions, hashes and compatibility of all active installed dependency requirements (all satisfied).

Paths below are relative to that site-packages directory; SHA-256:

| Imported artifact | Hash |
| --- | --- |
| `tenuo/__init__.py` | `6f5c3e620467bb0be38d08d9d6eaf9ed52fa39efb21a6f44f531f52136cd0878` |
| `tenuo/openai.py` | `9cf5b58e05109ae0166c56ddf3591f8d372859ca97f72bb3995fc9096c9cf3e1` |
| `agents/__init__.py` | `68fd43b0bc0ecc825722b65c24d1dd6972067f31632e1a8576187da347d8d436` |
| `tenuo_core/tenuo_core.abi3.so` | `cdab4164312a1a59f0f4978f9cc3c600b3dc575b39728a14656219873e3ce379` |

Used installed exports/signatures/docstrings and Python source: `Warrant.mint(keypair,capabilities,ttl_seconds,holder)`, `grant_builder().capability().holder().ttl().terminal().grant()`, `Warrant.sign(keypair,tool,args,timestamp)`, `Authorizer(trusted_roots,clock_tolerance_secs)`, `Authorizer.check_chain(chain,tool,args,signature)`, and `parse_strict_json(text)`. The wrapper never exposes the optional verifier `as_of` parameter to callers. Inspected `tenuo/warrant_ext.py`, `tenuo/builder.py`, `tenuo/openai.py`, `tenuo_core/__init__.py`, `agents/tool.py`, `agents/tool_context.py`, and dispatch locations in `agents/run_internal`.

`tenuo.openai.guard_agent` is absent. The installed agent guardrail extracts calls from input, rather than mediating later function execution. Agents 0.22.0 dispatch validates/coerces JSON, creates ToolContext, then calls the original function; its raw `FunctionTool.__wrapped__` explicitly bypasses framework hooks. Experiments showed Annotated strict integer metadata was lost during SDK schema creation: true and "20000" were coerced. The implementation validates original `ToolContext.tool_arguments` with strict JSON parsing, rejects unknown keys, signs those exact values and executes those verified values. The service separately enforces strict argument types.

Skill horizon snapshot was queried 2026-10-17T14:19:09.763226+00:00 against main `ba1efb55bb0548fdbd584b4653cdd6454b645193`; framework reference compares release v0.3.2 to historical main `283054366670c7021cf7a84d852690809bdbcec7`. These are hazard context, not dependencies used. No network refresh or external source was used; later horizon changes remain unknown.

## Validation

Commands run from this project:

- `.venv/bin/python .claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .` — completed; heuristic inventory confirmed function tool and fake effect, initial missing holder flow. Its scan also matched bundled skill metadata; findings were confirmed against application source only.
- `.venv/bin/python -m pytest -q` — final **38 passed in 2.27 seconds** (timing varies). Includes both original starter tests and 36 authorization cases.
- `.venv/bin/python scripts/runtime_probe.py` — successful; all active declared dependency requirements satisfied.
- `PYTHONPATH=. .venv/bin/python scripts/demo.py` — successful; measured output below.
- `.venv/bin/python -m compileall -q agent_app.py refund_service.py tests scripts` — successful syntax compilation. Neither mypy nor pyright is installed or configured, so no static type checker ran.

Tests prove allowed 1-cent, $200 and $500 calls via the real Runner dispatcher; wrong order, $500.01, $4,900, zero, negative, fractional, bool, numeric-string and huge amounts deny with zero effects. Receiving-service cases independently exercise missing/malformed/tampered credentials, wrong issuer trust, wrong holder signature, changed signed arguments, expiry, wrong capability, constraint violation and missing parent chain. Each asserts zero effect records. A narrower terminal child succeeds under root-only trust; widening that same parent envelope is rejected during delegation (not a receiving-boundary widening claim). Original FunctionTool direct invocation without authority and the raw wrapped handler with a valid but insufficient warrant both deny with zero effects. Runner without authority denies; a smaller warrant ceiling is enforced through Runner too.

Initial validation found eight failing cases: two SDK coercions, two incorrect test-context fixtures, two case-sensitive error assertions and two tests expecting a service exception rather than Runner's wrapping UserError. The implementation now checks raw input and tests use actual ToolContext and observed error types. Final suite passes. A subsequent raw-call test exposed a leftover asyncio marker warning; it was removed and the final suite passes without warnings.

Actual demo:

```text
Task warrant: refund_order(order_id="123", 1<=amount_cents<=50000)
Allowed: $200.00; effects=1
Denied: $4900.00; effects=0; Error running tool refund_order: outside refund policy
```

The $4,900 rejection is the service's independent policy ceiling; the smaller-warrant test separately proves cryptographic constraints are enforced. No real provider or payment requests occurred; tracing remains disabled, ScriptedModel is the only model, and the only effect is a list append.

## Scope and remaining limitations

Calls reaching RefundService execute only after the configured Tenuo verifier accepts the chain, holder proof, capability and constrained final arguments, plus the local ceiling. This covers the single fake refund path and enumerated denial cases.

Issuance, signing and verification share a mutable Python process. This prevents model-induced out-of-policy calls through these APIs but does not contain arbitrary Python execution: code can mutate the public fake effects list, private attributes, roots or implementation. That fake record mutation is not a separate payment API. Production requires independently operated issuance and effect ownership, protected keys and authenticated root configuration outside the untrusted agent process. Constructor root selection is trusted setup in this demo, not request input. Test-only minting is not the sole issuance path: `development_session()` is wired into `run_agent()`.

No replay cache, cumulative budget, idempotency, transactional deduplication, live revocation feed, approval collection, receipts or external execution evidence is implemented. Fresh PoP and TTL do not promise one-use or exactly-once effects. Authorized repeated calls may refund repeatedly. The terminal leaf cannot delegate further, but its holder can invoke its existing authority. Streaming is explicitly unimplemented by ScriptedModel; no claims cover streaming, process compromise, real network transports or other tools.

## Exact skill files read and scripts executed

Read these project-local skill files only (base `.claude/skills/tenuo-agent-authorization/`):

- `SKILL.md`
- `references/python.md`
- `references/native-tools.md`
- `references/framework-status.md` (including targeted OpenAI section read)
- `references/unreleased.md`
- `references/trust-levels.md`
- `references/common-footguns.md`
- `references/security-model.md`

Executed skill helper: `.claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .`. No other skill script executed. Application scripts executed: `scripts/runtime_probe.py`, `scripts/demo.py`, pytest collection of `tests/test_app.py` and `tests/test_authorization.py`, plus `compileall` over application/tests/scripts. Inline Python probes used `importlib.metadata`, `inspect.signature/getsource`, exports and method/docstring introspection, module paths, builder/warrant construction and one scripted positive smoke call; inline Python edits wrote the implementation/tests. Shell inspection used `pwd`, `rg`, `ls`, `cat`, `sed`, and read-only `git diff --stat` / `git status --short`. No other starter projects, previous results or rubrics were inspected. No delegation, commits or pushes were performed.
