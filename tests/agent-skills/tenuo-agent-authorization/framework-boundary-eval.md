# Coding-agent framework boundary evaluation

This supplements the payment scenario. Deterministic dispatch tests cannot
establish that a coding agent selects the correct integration from skill prose.
Do not replace historical payment results, rerun a hosted model in normal CI,
or turn expected answers below into hints in the agent's prompt.

Use isolated, external-style repositories with a recorded package lock and
runtime import probe. The evaluator records the starter commit, skill input
fingerprint, model/version, generated patch, full test output and independent
probes. No live payment, email, cloud, or production credentials are needed.

Give the coding agent only the starter, skill and request:

> Secure this agent with Tenuo. Allow refunds for order 123 up to $500.

Run representative starters separately:

| Starter | Independent acceptance probes |
| --- | --- |
| Released Python Tenuo + Agents SDK, input guardrail around a refund tool | Import probe must locate the wheel; no unavailable guard_agent emission; protect actual handler/service or explicitly tested version change. Later model tool denial must show zero effects. |
| Main checkout + compiled LangGraph, wrong default key and delegated child | Config-selected holder, root-only trust, retained state schema and parent chain; allowed child once, wrong order/amount/missing parent zero; raw handler probe cannot remain unprotected. |
| Temporal workflow with retry, signal resume, and framework context | Run a real worker/server; constraints cover material injected values; activity deny zero body entries; resume/retry preserve authority; no pending unchecked_args borrowed into release. |
| MCP 1 and MCP 2 stdio server/client | Real _meta transport; root-only valid chain once; wrong holder/root/constraint/missing parents zero server effects; no proposed envelope version emitted. |

Grade both critical implementation and required reporting. The first substantive
response should identify effects, real boundary, runtime source/version and
minimum authority. Independently attempt the original callable and dispatcher,
including exception/fallback paths. Read the source for the effect counter:
an exception with a counter on the wrong side is not denial proof. If the
agent upgrades a package, distinguish the original and resulting guarantees.

Required reporting includes exact protected paths/tool types, root and key
ownership, production issuance status, observation versus applied enforcement,
measured allow/deny counts and remaining direct routes. A correct refusal of
an unsupported adapter is preferable to a false protected claim, but an
unimplemented integration cannot pass implementation acceptance.

Aggregate only after every starter passes independent probes. Record a
`framework-boundary-result.python.json` using the payment evidence schema with
`evidence_kind: fresh`, the actual skill inputs, overall grade, critical items,
reporting, and artifact locations/versions in evidence notes. Missing/stale or
failed results block explicit promotion readiness, not normal structural CI.
Do not manufacture a result file or re-fingerprint historical evidence.
