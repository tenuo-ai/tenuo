# Security model and limits

Use this reference when deciding what an integration can honestly guarantee.

## What Tenuo can enforce

At a correctly placed verifier, Tenuo can reject calls whose presented authority fails the configured checks, including trust-chain, expiry, holder proof, capability, and supported argument constraints. Delegated authority is accepted only when it remains within the verified parent authority according to the protocol's attenuation rules.

These properties apply to the calls that pass through that verifier. They do not establish complete mediation for an application with unprotected effect paths.

## Trust assumptions

The guarantee depends on all of the following:

- The effect cannot be reached through an unverified path.
- The verifier and effect implementation are outside the attacker's authority for the threat being considered.
- Trusted roots are provisioned independently of the untrusted request.
- Issuer and holder private keys remain confidential and are used by the intended principals.
- The verifier receives the same material arguments that determine the effect.
- Constraint implementations and their surrounding canonicalization match the resource semantics.
- Time, revocation, nonce, and approval inputs are current when those checks are required.

State weakened assumptions rather than hiding them. For example, an in-process wrapper may be useful policy enforcement against accidental model behavior without containing arbitrary code execution in that process.

## Authorization versus adjacent properties

Keep these claims separate:

| Property | What establishes it |
| --- | --- |
| The call was within an authority envelope | Successful verification at the effect boundary |
| The caller possessed the holder key | Successful proof-of-possession verification |
| An identical presentation is rejected as a replay | Atomic nonce consumption |
| Repeated requests do not duplicate the effect | Application idempotency or transactional deduplication |
| The effect happened | Evidence from the effecting system, ideally transactionally recorded |
| The effect happened once | Idempotency or transactional deduplication at the effecting system |
| The agent followed the user's purpose | Not established by a warrant alone |
| Every application effect was mediated | Architecture review plus bypass tests |

## Constraint caveats

Constraint matching is only as meaningful as the value presented to it.

- Filesystem paths may involve symlinks, mount points, case rules, alternate encodings, and races. Resolve according to the platform at the trusted boundary, then use the resolved target.
- URLs may redirect or resolve to different addresses. Re-check relevant properties after redirects and apply network-layer controls where SSRF matters.
- Shell parsing and program behavior are larger attack surfaces than a command allowlist. Avoid shells for high-risk effects when a structured API exists.
- Custom expressions can encode subtle policy mistakes. Keep them small, test boundary cases, and obtain human review for high-impact policies.
- Wildcards and unknown-argument overrides intentionally leave authority broad. Use them only when that breadth is part of the approved envelope.

## Lifecycle caveats

- Short TTL limits exposure time but is not immediate revocation.
- A revocation mechanism helps only when verifiers receive and enforce sufficiently fresh revocation state.
- PoP prevents use by a party lacking the holder key; without nonce or idempotency it may remain replayable within its accepted time window.
- Terminal authority prevents further protocol delegation. It does not prevent the holder from asking another process to act through an interface the holder can already invoke.

## Safe claim template

Prefer claims that name the boundary and conditions:

> The `transfer` handler verifies warrants against the configured roots and checks holder proof, expiry, capability, amount, and destination before invoking the payment client. Tests show the client is not called for the enumerated denial cases. Redis-backed nonce consumption rejects an identical presented call during the configured window.

Avoid absolute statements such as “the agent cannot transfer elsewhere” unless all alternate credentials, clients, queues, and administrative paths have been excluded from the agent's authority and tested.
