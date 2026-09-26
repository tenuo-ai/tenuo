---
name: tenuo-denial-triage
description: Diagnose a denied Tenuo call and make the legitimate call work with the smallest change to authority. Use when a call, test, or agent step fails with a Tenuo denial, monotonicity, proof-of-possession, chain, expiry, approval, or unknown-argument error. Do not use to design new authority from scratch (use tenuo-warrant), to add enforcement to a boundary (use tenuo-agent-authorization), or for a review-only audit (use tenuo-audit).
---

# Tenuo Denial Triage

A denial is the system working. Find out whether the caller, the policy, or the configuration is wrong, then fix that with the smallest possible increase in authority. Never route around the verifier, and never make a test pass by widening what the agent may do.

**Announce at start:** "I'm using the tenuo-denial-triage skill to find why this call was denied and the narrowest fix."

## Collect the facts before changing anything

1. **The exact error.** Class or code, message, hint, and the field or tool it names. Keep the text; do not paraphrase it away.
2. **The decision point.** Which verifier denied: an in-process guard, an MCP server, a gateway, a sidecar, a worker. And which link: root trust, an intermediate warrant, the leaf, the proof-of-possession, or an approval gate.
3. **The presented authority, from the SDK's own diagnostics, not from reading code.** In Python, `why_denied()` on the warrant for the exact tool and arguments, `diagnose()` on the warrant, `explain()` on the caught error, and `info()` for configuration. In TypeScript, `session.inspect()` and `tenuo.explain(session, tool, args)`. In Rust, the `Diagnostics` helper's `explain_denial`, `why_denied`, and `explain_authority`. From a shell, `tenuo inspect` and `tenuo verify`. When the denial happened in another process, start from the receipt: its decision code, action, request hash, and trusted-roots hash say what the verifier saw. Confirm every diagnostic name against the installed package version before relying on it.
4. **The call as the verifier saw it.** Tool name, every argument after normalization and injection, the holder key that signed, and the timestamp. Argument names and types matter as much as values.

Write a one-screen triage note before editing:

```text
Error:          <class or code>: <message>
Denied check:   tool | constraint(<field>) | unknown field | expiry | PoP | chain | monotonicity | revocation | approval | configuration
Decision point: <component> at <file:line or service>, chain link: <root | intermediate | leaf | PoP>
Presented:      tools=<...> constraints=<...> holder=<key id> expires=<...>
Call:           tool=<...> args=<normalized map> signer=<key id>
Cause:          caller | policy | configuration | expected denial
```

## Classify the denial

| Denied check | What it means | Usual cause |
|---|---|---|
| Tool not authorized | The warrant never carried this tool | Caller named the wrong tool, or the issuer never granted it |
| Constraint on a named argument | The value is outside the envelope | Caller sent the wrong value, or the envelope is narrower than the legitimate task |
| Unknown field, closed-world | The call carries an argument the policy never named | Caller sends something the effect does not need, or a needed argument was never named |
| Expired | Stale authority | Holder reused a warrant past its TTL |
| Proof-of-possession, wrong holder, signature mismatch | The proof does not match the leaf holder, tool, or arguments | Wrong signing key, arguments changed after signing, tool string mismatch, clock skew |
| Untrusted root, broken chain, parent required | The verifier does not trust or cannot link the chain | Wrong issuer for this verifier, parents not presented, chain assembled out of order |
| Monotonicity | A child claims more than its parent | Delegation design widened instead of narrowing |
| Revoked | Authority was withdrawn | Expected; do not resurrect |
| Presentation context: audience, nonce, replay | The proof was not made for this enforcement point, or was already used | Caller or transport: present to the party you address, with a fresh proof per call; never disable the check |
| Approval required or insufficient | A gate fired | Expected; obtain approval or narrow the exemption |
| Configuration | No trusted roots, no warrant in context, missing key | Wiring, not authority |

An expected denial is finished when you say so. Do not turn it into a change.

## Rank the fixes and stop at the first that works

1. **Fix the call.** Right tool name, right argument names and types, values normalized the way the verifier normalizes them, the proof signed by the leaf holder over the final arguments, a fresh warrant instead of a stale one. If the effect never reads an argument, remove it from the presented call; do not name it in the policy. A value is material when the effect stores, forwards, logs, or acts on it, even if it does not change which effect runs; a material value needs a bounded constraint, never a wildcard. Do not change the effect to consume a value in order to justify naming it.
2. **Stay inside the envelope.** If the task is narrower than the warrant, narrow the child. If the issuer can mint authority that fits the task, request that warrant. Neither changes any policy.
3. **Widen minimally, at the issuer, by naming exactly the new legitimate values.** Add the one recipient to the allowed set. Raise a maximum to the number the task needs. Name a newly required argument with the tightest constraint that admits the real values: an exact value, a small set, a bounded range, a path under a root, a URL limited to named domains. Free text the effect keeps gets a regular expression that bounds its length and character set, where the SDK offers one. If it does not, use another supported bounded constraint, such as an exact value or a small allowlist. Keep every material value in the signed and verified arguments. If no supported constraint fits, remove the value from the entire call, including the effect, only when the task permits omission; otherwise stop and report the unsupported requirement. Removing a value only from the presentation leaves the effect consuming unchecked data. Keep the TTL and delegation depth as they were.
4. **Last resort, with a written justification in the report:** an unconstrained wildcard on a named argument that the call must carry and the effect ignores. Never on a value the effect keeps.

Never do these to clear a denial:

- Opt out of closed-world mode (`_allow_unknown` or its equivalents) to admit an unknown field. Name the field or drop it.
- Leave the capability open to any arguments, whether by a policy that names none or by the SDK's explicit any-arguments form, or put a wildcard or a match-everything pattern on a material argument: one the effect stores, forwards, logs, or acts on.
- Remove a constraint, or replace a path or URL constraint with a plain string glob.
- Lengthen the TTL because a warrant expired. Re-issue instead.
- Add the caller's own key, a test key, or any new root to the verifier's trusted roots.
- Enable an optional-warrant, observe-only, shadow, or development mode on the verifier.
- Catch the denial and call the effect anyway, or add a route to the effect that skips the verifier.
- Edit verifier trust, proof-of-possession, or gate settings from the caller's side. Those belong to the verifier's owner, who changes them through their own review.

If the only fix you can find is on that list, stop and report that the request needs new authority from the issuer or a design change. Hand new authority design to `tenuo-warrant` and missing enforcement to `tenuo-agent-authorization`.

## Prove the fix

- The previously denied legitimate call now reaches the effect exactly once, through the same path the application uses.
- Every previously denied illegitimate case still produces zero effects. Rerun the existing denial tests; do not delete or weaken one to make the change fit.
- Add a test for the new boundary: the value just past the widened edge is still denied.
- If the preferred constraint is unavailable, prove that the fallback still verifies the material value, or that omission removes it from the effect as well. When neither is possible, the call must remain denied with zero effects.
- If you changed a policy, state the authority delta as before-and-after envelopes, one line per changed capability or argument.

## Report

```text
Denied check:     <from the triage note>
Decision point:   <component>, chain link <...>
Cause:            caller | policy | configuration | expected denial
Fix applied:      <one sentence>
Authority delta:  <capability.argument>: <before> -> <after>   (or "none")
Unchanged:        verifier trusted roots, proof-of-possession, closed-world mode, TTL, delegation depth
Tests:            <n> prior denials still zero effects; legitimate call allowed once; new edge denied
Residual risk:    <what the widened envelope now admits that it did not before>
```

Do not claim the fix proves replay resistance, revocation, exactly-once execution, or that the effect completed downstream. If the denial revealed a missing or bypassable boundary, say so and route that work to `tenuo-agent-authorization`; a review-only question about what a warrant permits goes to `tenuo-audit`.
