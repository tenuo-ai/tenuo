# Refund authorization implementation

Authorization result: **development loop**. In-process guardrail: **yes**.

Implemented one local vertical slice in `agent_app.py`, using only the fake `effects` list and scripted LangGraph dispatch. No network/model calls or real refunds were made. No commits or pushes.

## Exact guarantee

Calls reaching the configured refund handler record a fake refund only after a Tenuo `Authorizer.check_chain` accepts the root-to-leaf public warrant chain, holder proof, lifetime, capability `refund_order`, and final arguments. Roots are captured from explicit graph construction configuration, not request state. A separate local ceiling requires order ID exactly string `123` and an integer amount of 1 through 50,000 USD cents inclusive. Strict schema fields reject boolean, string and fractional amounts. Verification and the effect use the identical argument dictionary.

The caller-side `run_refund` creates proof using the `refund-worker` key; transport to the receiving handler contains only base64 warrant tokens and signature bytes, in injected `RunnableConfig`. No private key is passed to or used by the verifier. The original `agent_app.refund_order.invoke` route and its underlying `.func` both raise before any effect. The compiled graph registers a new handler whose effect is inline after verification; there is no raw refund helper behind it.

`task_authority()` is the application development issuance entrypoint. It creates an ephemeral issuer, parent holder and worker. Root TTL is 300 seconds; worker child TTL is 120 seconds and terminal. Only the issuer public key is trusted, and the full parent chain is required. The worker key registry also contains a different default key; successful application dispatch uses the worker explicitly. No delegation is performed during dispatch.

## Measured validation

Executed `.venv/bin/python -m pytest -q -s`: **19 passed in 1.42s**. This is the complete project suite, including the updated starter tests. Every denial test asserts an empty effect record and checks the error reason. Tests exercise actual `StateGraph.compile()` and `ToolNode` dispatch with injected config, not merely direct verifier calls.

Measured demonstration:

```text
Task warrant: refund(order=123, amount<=500 USD)
Allowed: refund(order=123, amount=200 USD) -> effects=1
Denied: refund(order=123, amount=4900 USD) -> effects=0
```

Coverage: positive delegated call with root-only trust; 1 and 50,000 cent edges; different order; 50,001 cents; zero; negative; huge integer; boolean/fraction/string coercion; missing/malformed presentation; untrusted issuer; wrong-holder signature; missing chain; wrong capability; narrower warrant amount constraint; proof signed for different final arguments; unknown extra argument included in proof; expired warrant; original `.invoke` and `.func` routes. A valid narrower terminal child succeeds, then a widened child is rejected by the SDK grant builder before dispatch. This last test proves issuer-side attenuation rejection, not independently forged child acceptance/rejection at the receiver.

Executed `.venv/bin/python -m compileall -q agent_app.py tests/test_app.py`: exit 0. No project type checker is configured; mypy and pyright are not installed, so no static type-check result is claimed. Tests were run once after implementation; no second implementation pass was made.

## Runtime and source probes

- Python 3.12.11, Clang 17.0.0; executable `/private/tmp/tenuo-local-agent-evals/framework-langgraph/.venv/bin/python`.
- Tenuo distribution 0.3.2; editable import `/Users/danieljoseph/Claude/Tenuo/tenuo-skill-readiness/tenuo-python/tenuo/__init__.py`. Distribution `direct_url.json` confirms that editable directory.
- `SDK_SOURCE.json` and requirements lock declare commit `abe73aab4df50a7044ab8b0d560b061c2b57d650`; `git -C /Users/danieljoseph/Claude/Tenuo/tenuo-skill-readiness rev-parse HEAD` returned the same commit. No dependency changes.
- Native artifact `/private/tmp/tenuo-local-agent-evals/framework-langgraph/.venv/lib/python3.12/site-packages/tenuo_core/tenuo_core.abi3.so`, SHA256 `b619ec542fd7497f3bfc690ffd4b025769809b071238ce263dfc189ad7385742`.
- Imported Tenuo `__init__.py` SHA256 `6f5c3e620467bb0be38d08d9d6eaf9ed52fa39efb21a6f44f531f52136cd0878`; adapter `tenuo/langgraph.py` SHA256 `ec1d5c6631dce8ba8344a27b0c15feb1bdff8557d37b9c0edbe22bde12420230`.
- LangChain 1.3.18; langchain-core 1.6.12; LangGraph 1.2.11; langgraph-prebuilt 1.1.1; pytest 9.1.1. Imported `langgraph/prebuilt/tool_node.py` SHA256 `433aecca1f020addea7425196443d1c4185f328ba2ceeda94f48fb625b496ab3`.
- Inspected exact imported `tenuo/langgraph.py` sync authorization and ToolNode wrappers, key/config resolution and parent-chain paths, plus `_enforcement.py` use of `Authorizer.check_chain`. Used runtime signatures/docstrings for `Authorizer`, `check_chain`, `authorize`, `authorize_one`, `Warrant.sign`, `guard`, `TenuoToolNode`, and grant-builder exports. `check_chain` takes root-to-leaf warrants and proof; no request-controlled `as_of` is exposed by this implementation.
- Initial speculative `tenuo._core` import failed; corrected native probe to `tenuo_core.tenuo_core`. A mint-builder `terminal` probe failed; runtime grant-builder inventory confirmed `terminal()` there. Some exploratory `rg` paths did not exist; these were not validation results.

## Remaining limitations

This is a process-local fake-effect development loop, not a production boundary or arbitrary-code sandbox. Issuance, holder keys, graph construction, trusted-root configuration, verifier and the mutable fake record share a Python process. Hostile code could replace those objects or append directly to the fake record. Production requires an independently operated issuer and effect service with separate credentials, fixed trust configuration, and protected holder keys.

The guarantee is per invocation, not a cumulative $500 budget: multiple valid requests can each refund up to $500. No replay cache, idempotency, exactly-once execution, immediate revocation feed, approval workflow, or execution receipt was implemented or claimed. Proof may be replayable during its accepted window; TTL is not revocation. Default Authorizer PoP-window settings remain in effect; clock tolerance is explicitly zero. There is no real payment client or deployed isolation to assess.

The framework may discard unknown tool fields; the tested extra-field presentation fails because its proof binds arguments different from those executed. Only order and cents materially affect this fake effect. Built-ins, handoffs, checkpoint/resume, asynchronous dispatch and remote transport do not exist in this starter and were not added or certified. This custom handler uses the official core verifier rather than relying on a framework adapter hook to cover raw handler access.

The skill's horizon snapshot is dated 2026-10-17T14:19:09.763226+00:00 and is hazard context only. No live remote horizon refresh was attempted, and no pending API or version upgrade was used.

## Skill files and scripts read or executed

Exact skill files read (all under this project's `.claude/skills/tenuo-agent-authorization/`):

- `SKILL.md`
- `references/trust-levels.md`
- `references/native-tools.md`
- `references/python.md`
- `references/framework-status.md`
- `references/unreleased.md` (the initial combined read exceeded tool output limits; snapshot header was subsequently read explicitly)
- `references/common-footguns.md`
- `references/security-model.md`

Executed skill script: `.venv/bin/python .claude/skills/tenuo-agent-authorization/scripts/inspect_native_tools.py --root .`. It found the original unguarded tool and graph registration; findings were confirmed in application source. It also scanned project-local skill reference text. No SDK tests, agent-skills, evaluation results/rubrics, other starter projects, or other conversation were read.

Other scripts executed: inline Python probes for imports/distribution versions, signatures/docstrings/builder exports, artifact paths and SHA256 hashes; project pytest suite; compileall. Shell inspection commands were `pwd`, `rg`, `cat`, `sed`, `head`, and the read-only Git commit probe. Application and test files were written by shell heredoc; this report was written the same way. No browser, external tools, delegation or package installation was used.
