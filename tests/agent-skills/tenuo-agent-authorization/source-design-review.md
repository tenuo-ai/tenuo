# Project onboarding and deployment design review

Reviewed 2026-10-17. This is source/design review and executable example evidence,
not a new coding-agent evaluation. Historical evaluated inputs stay unchanged.
No PR is opened; Daniel's manual testing remains required.

## Source authority

- Core main SDK sources: `ba1efb55bb0548fdbd584b4653cdd6454b645193`;
  `tenuo-core/src/planes.rs`, framework source/status and `docs/enforcement.md`.
  Implementations outrank broad documentation claims about universal adapter
  behavior. Existing deterministic dispatch results remain separately recorded.
- IETF -02 working branch: `aat/ietf-vectors-02`, PR #667, commit
  `ba7878bc72c3f5d289a75051029209d30741b306`. Read introduction/design goals,
  terminology, invariants, confused deputy/compromised holder/enforcer limits,
  replay/audience, revocation, approvals, role separation and CBOR considerations.
  #666's engine-conformance changes remain pending; no draft APIs installed.
- Demos: current main `936b3c77c1a2b27b78933713bd2626ede416651d` (checked
  against GitHub). Inspected invoice-processing local/Cloud paths, OpenAI/MCP
  delegation server/authority structure and deterministic-case instructions,
  Temporal order-repair issuer/template/public-key worker, and incident/Claude
  Temporal lifecycle documentation. Full demo stacks were not rerun in this pass.
- Cloud: current main `54516d532b4ce0d61c7857527c53758bfa9071e8` (checked
  against GitHub). The local working tree was 270 commits behind; read committed
  current origin/main objects without changing that checkout or its local files.
  Inspected service template/trigger/fire/authorizer/KMS contracts, Python SDK
  connect/providers/enforcement/Temporal helpers and deployment/pipeline docs.
  No private source, credentials or operational configuration copied here.

## Design decisions carried into the skill

1. Separate management/issuance from effect enforcement. Application-owned
   issuance and Cloud management can both support locally verified task grants.
   Do not require a control-plane round-trip on every invocation or delegation,
   or imply that offline verification eliminates refresh/approval dependencies.
2. Recommend deployment from actual threat/bypass routes and credential
   ownership. Trusted in-process enforcement is useful; arbitrary agent-process
   compromise requires a protected service/host/worker or forced proxy boundary.
   More containers alone do not establish mediation.
3. Derive scope from trusted task/business records, not a model plan or poisoned
   note. Cloud template, trigger event binding and local YAML request are distinct
   contracts. Resolve both core and Cloud runtimes before emitting either API.
4. Keep parent holder keys and broader usable credentials away from child agents.
   Parent authority is not revoked by deriving a child. Planning/tool roles are
   deployment choices; root/leaf positions are not universal issuer/execution
   token types in the draft.
5. Preserve all chain invariants, especially structural containment. Do not
   import JWT typing, audience or JTI replay semantics from the pending draft
   into the released CBOR/COSE API. Revocation/approval profiles and binding
   formats need separate source verification.
6. Inspect Cloud convenience defaults. Reviewed Cloud enforcement helpers default
   to observe, and some Temporal helpers derive roots from their signing key.
   Explicit root ownership and enforce-mode tests are required; copying a
   convenience constructor is not proof of independent verification. Receipt
   event transport and native signed-artifact sinks are also distinct.
7. Lead with useful autonomy: same tool, trusted task context, permitted effect,
   changed destination/task or attempted child-scope expansion. Do not claim
   RBAC/OAuth/policy engines can never enforce argument limits. Model-selected
   bad calls are forced for deterministic proof, not a measured injection rate.

## Executable first example

`tenuo-python/examples/task_authority.py` is a short core-only development demo,
not a replacement for framework dispatch recipes. Its script metadata pins
Python 3.12 and released `tenuo==0.3.2`. One command from the repo root:

```bash
uv run --no-project tenuo-python/examples/task_authority.py
```

It pays the trusted invoice for $200 once, rejects an injected bank change,
rejects the child's $400 attempt despite the parent's $500 ceiling, and rejects
another invoice. Each denied call is signed by the real holder and reaches the
receiving Authorizer; zero fake effects are asserted. No provider account, Cloud
account, Docker or model key required. Per-call limits do not establish a total
budget, replay suppression or idempotency. Co-located ephemeral keys are a
development loop; deployment isolation is not demonstrated.

Validation initially caught an unsupported MintBuilder.max_depth call. It was
removed; the released high-level mint builder retains its default parent depth
ceiling and the child is terminal. Do not invent a high-level setter or describe
that parent ceiling as one. Additional transport/type negative tests use the
actual receiver and check denial reasons, with valid positive controls.

Tests/command outputs and runtime provenance are recorded in
`onboarding-quickstart-results.json`. These deterministic checks do not certify revised prose. A subsequent fresh
blind project-onboarding diagnostic, including absent-template-parser fallback
and deployment/key-ownership choices, passes 23 independent HTTP tests; see
project-onboarding-result.python.json. Further framework/Cloud/CLI and routing
coverage remains necessary before broader promotion. Per-framework short canonical examples are still a distribution gap;
the existing four framework diagnostics and demo topology references remain
distinct from this core first-run example.
