# Apply Tenuo to this project

Start with the user's useful outcome and the code that performs it. Explain what
the agent will be free to decide inside its authority. Match the project's
language and existing framework; do not begin with a Tenuo glossary or replace
the application with a stock demo.

## Inspect, then propose

Trace the entrypoint, agent/tool registration, final effect handlers, credential
ownership and alternate routes. Resolve the actual Tenuo and framework code,
then consult framework status and pending fixes. Existing roles and OAuth scopes
can remain in place: identify the task-specific limits the integration adds.

Use [Deployment choices](deployment-choices.md) to recommend issuance/management
and effect enforcement separately. Infer existing topology and credential
ownership from code and deployment manifests before proposing new infrastructure.
Include the chosen model and key owners in the first proposal; Cloud is an
optional management choice, not a replacement for a protected effect boundary.
For a new integration, start with the installed local SDK or supported local CLI.
Deliver a useful allow/deny demonstration before introducing optional Cloud
setup. For an existing Cloud project, use its verified issuance path rather than
replacing it with local key management. For migration, follow the staged plan in
Deployment choices and preserve the task envelope and effect-boundary tests.

Infer candidate limits from trusted configuration, schemas and application logic.
Tool descriptions, retrieved documents, model output and observed calls reveal
possible actions; they do not grant business authority. Do not turn the largest
observed payment into an approved budget or a customer-supplied destination into
an authorized payee. State assumptions and ask about material unresolved limits.
Keep testing and inspection moving while awaiting a business decision.

The first proposal should fit on a screen. For example, after confirming these
values with the application/task owner:

```text
Task: resolve the damaged-item claim for order 123.
Autonomy: choose a refund amount without asking again inside the approved limit.
Effect: refund_order.
Boundary: refund service, before its payment-provider call.
Deployment: application-owned issuer; independent refund service verifies locally.
Authority: order=123; refund<=500 USD; original payment only; expires in 10 min.
Delegation: optional specialist gets <=250 USD for 2 min, no further delegation.
Delivery: installed SDK issuance code; YAML only if its parser is available.
Proof: refund 200 succeeds; an injected refund to another payee executes nothing.
```

These are illustrative limits, not defaults for the user's project. A task may
need only local constraints; do not require warrants, delegation or approvals
when the user chose that mode. For a warrant-based task, explain the concrete
issuer, holder, verifier and root ownership in the project.

## Produce an authority artifact the project can use

Map each required effect to its actual tool name and material arguments. Name
units, tenant/account/resource identifiers, destinations, environments and TTL.
Constrain final normalized arguments, including meaningful framework defaults.
Where a trusted service resolves the original payment itself, constrain the
order and keep that resolution server-side rather than introducing a
caller-selectable payment destination just for the example.

Distinguish three artifacts:

- A policy proposal describes intended authority; it is not executable SDK/YAML.
- A warrant grants concrete authority to a holder. Task-derived values such as
  the current order must be resolved from trusted task context before issuance.
- A template proposes reusable issuance rules. Its parameters and approval
  limits need a trusted issuer-side validation path; editing a template does not
  change already signed grants.

Produce SDK issuance code using the installed APIs, or a template/request only
after inspecting the installed parser's actual schema. Never invent YAML by
translating SDK constraint names, placeholder interpolation or future PR syntax.
If templates are unavailable, provide working code-first issuance; do not silently
upgrade or stop at a speculative template. Validate the artifact with the actual
SDK/parser and demonstrate that it mints the intended bounded authority. Keep
issuer private keys outside the agent/verifier in deployment; local ephemeral
keys establish a development loop only.

For a standalone issuance/delegation task, use tenuo-warrant if installed. For
project onboarding, keep ownership of the end-to-end integration: a warrant
artifact alone is not completion. Do not bounce the developer between skills.

Default to task authority with no unnecessary delegation headroom. If delegation
is useful, explain what the parent may choose, what the child may choose, and
why the child's signature cannot widen the parent envelope. Transport the full
chain to root-only verification. A task that outlives its grant needs a renewal
plan. A per-call maximum is not a total budget; cumulative limits, one-use grants
and exactly-once effects require additional stateful controls.

## Demonstrate useful autonomy quickly

Use one short example in the user's domain, with one run command and no provider
key required for the local demonstration. Keep setup and framework scaffolding
out of the explanation. Use an actual framework dispatch path with fake effects.
When substituting scripted model calls, say that plainly: force a malicious call
instead of depending on whether a particular model obeys a prompt injection.

Show one successful business action and a refusal of the same tool with an
out-of-task resource, destination, amount or delegated scope. A counter/journal
at the effect boundary must show one allowed effect and zero denied effects.
Display the trusted task envelope separately from the attempted arguments.
For example: parent permits 500; child permits 250; child attempts 400 and is
denied even though it remains inside the parent's ceiling.

Do not claim prompts cannot be injected, that every other authorization system
lacks argument constraints, or that Tenuo proves human intent. The demonstrated
property is that a bad model-selected call cannot exceed verified authority
through the protected boundary. Name remaining raw routes and deployment limits.

## Respect each integration's design

Explain only the choices that affect this project, using the exact-version source:

| Surface | Decisions that change the guarantee |
| --- | --- |
| OpenAI Agents | Tool calls occur after input guardrails. Check function, MCP, handoff and hosted tool coverage separately; use a guarded service when the installed adapter cannot mediate the path. |
| LangChain / LangGraph | Compiled config must reach the selected holder key; state must retain parent chains. Verify ToolNode, middleware and any executor fallback with the actual dispatcher. |
| Temporal | Carry public authority through workflow history to activity ingress. Account for injected arguments, retries, suspension, expiry and replay; workflow determinism is not activity idempotency. |
| MCP | Agree on the installed metadata carrier, defaults/canonicalization and SDK major. Enforce at the server effect boundary; client-only checks leave a direct server route. |
| CrewAI / ADK / AutoGen | Establish actual callback cancellation/exception behavior and guarded tool scope; a registered hook alone does not prove mediation. |
| FastAPI / A2A | Trace router/handler coverage or protocol dispatch, chain/PoP transport and replay ordering; protect alternate routes too. |
| Hermes | Verify the separate plugin checkout, session/child-session attachment and actual server enforcement. Attachment is not issuance or revocation. |

The framework status reference records current evidence and known gaps. These
decision prompts are not a claim that every adapter/version has been tested.

For a standalone first look when working in the Tenuo repository,
`tenuo-python/examples/task_authority.py` runs with
`uv run --no-project tenuo-python/examples/task_authority.py` from its root.
Its script metadata pins the released Python SDK; it needs no model key, Cloud
account or services. It pays a trusted invoice once, then refuses a diverted
bank account, a child's attempted use of the parent's larger limit, and another
invoice. This is a core development example, not proof of any framework adapter.
Do not require cloning a demo just to secure the user's existing project.

The same task has short real-dispatch examples under
`tenuo-python/examples/task_authority_frameworks/`: OpenAI Agents, LangGraph,
Temporal and MCP 1/2. Its README lists one run command per framework and exact
scope. All use released SDK APIs and local fake effects; the generic service
recipes do not establish coverage of an official framework adapter. Use them to
explain the value, then prove the user's actual integration separately.
