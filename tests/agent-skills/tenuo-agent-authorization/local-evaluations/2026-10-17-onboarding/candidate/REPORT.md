# Onboarding implementation report

Initial proposal, sent before implementation: protect the existing worker HTTP payment effect, use an application-owned approval-service issuer with public-root-only worker verification, and give the agent useful autonomous partial-payment authority for INV-123 / verified-bank / USD cents 1..1,420,000. Use installed SDK code-first issuance, five-minute terminal execution authority, no Cloud account or dependency upgrade. Separate process ownership is the intended deployment, not proof of local isolation.

## Final choices and usable authority

`authority.issue_invoice(issuer_key, holder_public_key, invoice_id)` is a reusable SDK issuance template, not speculative YAML. It reads status, currency, bank and limit from trusted approved_invoices.json. The note requesting attacker-bank is untrusted and cannot grant authority. Currency is fixed to USD by trusted record validation and the worker API; there is no caller-selected currency field.

The actual installed Warrant.issue() defaults to delegation depth 64 and does not expose a terminal setting. The implementation therefore signs a task-bounded 360-second issuer warrant and issues a 300-second terminal execution warrant for pay_invoice. The issuer owns both issuance signatures; the agent holds only its holder key and public warrants. The worker receives a two-warrant root-to-leaf chain and base64 holder proof, verifies against its independently supplied issuer public root with zero clock tolerance, checks final exact strings and losslessly represented positive integer cents, and executes those same arguments. No receiver signing key or request-controlled verification clock exists. Unknown arguments fail closed.

The recommended deployment retains the existing payments-team-owned worker and approval-service-owned issuer. Provider credentials and approval records must remain outside agent ownership. Agent network access should reach only the protected worker, and must not include direct provider credentials or unguarded payment routes. Cloud could later manage issuance/identities/revocation but is unnecessary for this local start; no Cloud runtime was installed, inspected or claimed. No framework adapter is needed for this custom HTTP dispatcher.

The worker also rechecks its trusted approval snapshot and atomically caps cumulative invoice payments under a local lock. This is an application control in addition to the signed per-call envelope. The local counter resets on restart; production requires transactional durable accounting and provider idempotency before real money is used.

## Evidenced guarantee and limits

Authorization result: **development loop**. In-process agent guardrail: no; enforcement is at worker.Handler.do_POST, the original effecting handler. Calls reaching that boundary append a fake payment only after configured-root chain, holder proof, expiry, tool and argument checks and local approval accounting succeed. Direct unsigned HTTP requests to the original handler produce zero effects.

This is not production containment: demo.py creates ephemeral issuer/holder keys in one developer process and the developer can edit all files and import worker.effects directly. There are no actual OS/service ownership controls, production secret management, TLS/workload identity, durable budgets, atomic provider transactions, revocation distribution, one-use nonce consumption or signed completion receipts. Replay may repeat an authorized payment within the remaining local invoice budget; proof-of-possession is not replay prevention. Terminal warrants prohibit protocol delegation, not relaying calls using the same holder. Approval records establish business authority at issuance and worker startup; changes need refresh/renewal, and signed authority does not prove human intent or downstream payment completion. The fake journal is local test evidence only. No live-model injection experiment was run: malicious arguments are scripted explicitly.

An initial regression found that this SDK accepts the execution leaf alone when the same independently trusted root key directly signed it. The worker now explicitly requires this application's complete two-warrant issuance transport. This is an application requirement; we do not claim missing-parent rejection is an unconditional SDK property. No intermediate key was added as a trust root.

## Sources and exact runtime

Python 3.12 virtual environment in this project, tenuo distribution 0.3.2, pytest 9.1.1. The resolved import is `.venv/lib/python3.12/site-packages/tenuo/__init__.py`; native artifact is `.venv/lib/python3.12/site-packages/tenuo_core/tenuo_core.abi3.so`. Distribution has no direct_url.json. Wheel metadata: maturin 1.15.0, cp39-abi3-macosx_11_0_arm64. No claim of an immutable repository commit is made for this installed build, whose exported APIs differ from historical skill release notes.

SHA256 tenuo/__init__.py: `6f5c3e620467bb0be38d08d9d6eaf9ed52fa39efb21a6f44f531f52136cd0878`.
SHA256 native artifact: `cdab4164312a1a59f0f4978f9cc3c600b3dc575b39728a14656219873e3ce379`.

Inspected installed exports, docstrings and inspect.signature for Authorizer, check_chain, authorize_one, authorize, Warrant.issue, issue_issuer, mint, mint_builder, sign, SigningKey and Range; installed builder.py, warrant_ext.py, bound_warrant.py, _builder.py, and WHEEL metadata. The installed source confirmed issuer constraint_bounds is a flat argument mapping. No external project, core tests, previous evaluation, grading rubric or online source was consulted.

## Commands, corrections and results

- `.venv/bin/python .claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .`: completed; heuristic output included skill-reference false positives, manually confirmed actual project native path agent.pay_invoice -> HTTP worker.Handler.do_POST -> effects.append.
- Initial `.venv/bin/python demo.py`: failed on incorrect nested issuer constraint_bounds; corrected to flat limits using installed builder docs. Next attempt reached the server but sandbox disallowed loopback socket binding. Authorized sandbox escalation for local-only sockets succeeded.
- `.venv/bin/python demo.py`: ALLOW approved partial payment effects=1; DENY injected bank diversion effects=0; DENY amount above approval effects=0. No external calls or payments.
- First `.venv/bin/python -m pytest -q`: 15 passed, 2 failed. Fixed mandatory full-chain transport and the expected widening error text (actual RangeExpanded/monotonicity violation).
- Second full suite: 19 passed in 11.70s, including positive and denied HTTP dispatch, missing/malformed/tampered authority, wrong holder/proof, untrusted issuer, expired authority, wrong capability, missing chain, invoice/payee/amount boundaries, invalid numeric types, unknown arguments, direct original worker route, terminal delegation and widening issuance rejection. Terminal and widening rejection are issuance-side checks with a working positive control, not fabricated receiver-side delegation evidence. No delegated subagent is needed or recommended here.
- Added cumulative local invoice ceiling regression and reran full suite; final result recorded below.
- `.venv/bin/python -m compileall -q agent.py authority.py worker.py demo.py tests`: passed before final small cumulative accounting addition; final compile repeated below. No type checker is installed (`mypy` absent), so no static type-check result is claimed.

Exact skill files read, all under `.claude/skills/tenuo-agent-authorization/`: `SKILL.md`, `references/project-onboarding.md`, `references/deployment-choices.md`, `references/trust-levels.md`, `references/python.md`, `references/native-tools.md`, `references/framework-status.md`, `references/unreleased.md`, `references/common-footguns.md`, and `references/security-model.md`. Combined initial output was truncated; relevant Python/native/trust references and horizon headings were read again separately. No other skill script was executed. Project scripts executed: demo.py and tests/test_starter.py via pytest; inline Python performed SDK introspection, hashing, and local file edits. No installs, upgrades, commits, pushes, model calls or delegation.

Final validation: `.venv/bin/python -m pytest -q` **20 passed in 12.20s** (including cumulative-ceiling test); final `.venv/bin/python -m compileall -q agent.py authority.py worker.py demo.py tests` exited 0. The final cumulative-accounting change does not alter the demo's arguments or printed authorization outcomes.
