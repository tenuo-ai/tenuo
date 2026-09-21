# Common footguns

Read this reference before declaring an integration secure or production-ready. Apply only the findings relevant to the chosen architecture, but do not omit one merely because a framework wrapper makes the happy path work.

## Boundary and bypass mistakes

**Calling an in-process wrapper a sandbox.** A wrapper constrains calls that reach it. It does not contain arbitrary code in the same process when that code can call the filesystem, network, SDK, or credential directly. Move verification to an independently trusted effect boundary or state the weaker model.

**Leaving the original credential or route available.** Protecting one tool is ineffective if the agent can use the underlying API key, database client, queue producer, administrative endpoint, or alternate tool. Inventory and close every route to the effect.

**Verifying after the effect.** Logging, callbacks, or post-tool hooks cannot prevent an action that already ran. The verifier must complete successfully before the first irreversible operation.

**Failing open through framework behavior.** Exceptions, timeouts, retries, streaming fallbacks, and optional middleware can skip a check. Test each framework path and map denial to a terminal outcome.

## Trust and key mistakes

**Accepting the trusted root from the request.** A valid signature is meaningless if the caller chooses what is trusted. Provision roots independently and authenticate updates.

**Putting private keys in prompts or serializable agent state.** Keep issuer and holder keys out of model context, logs, checkpoints, messages, and warrant serialization. Store only public identifiers or opaque key references where possible.

**Co-locating the warrant and holder key without acknowledging the threat model.** PoP helps when a warrant is copied without its key. If an attacker can exfiltrate both, that protection is lost. Isolate signing material when defending against arbitrary code or process compromise.

**Letting the receiver sign for the caller.** The effecting service should verify holder proof, not manufacture it using a shared holder secret. That collapses caller binding.

## Argument and policy mistakes

**Authorizing one representation and executing another.** Defaults, aliases, URL decoding, path resolution, Unicode normalization, redirects, and framework coercion can change meaning. Normalize once at the trusted boundary and execute the verified representation.

**Ignoring framework-inserted defaults.** A defaulted destination, method, tenant, namespace, or limit can materially change the effect even if absent from the model's call. Include effective values in authorization.

**Assuming host schemas are authorization.** Type and shape validation answers whether input is valid, not whether this holder may perform this effect. Apply both schema validation and authority checks.

**Opening the policy for convenience.** Wildcards, unknown-argument overrides, empty ceilings, broad URL patterns, and permissive custom expressions can remove the intended restriction. Inspect the installed SDK's exact semantics and justify each broad field.

**Treating URL or command validation as isolation.** URL checks do not replace redirect, DNS, proxy, and egress controls. Command token checks do not turn an unrestricted shell into a safe sandbox.

**Missing time-of-check/time-of-use changes.** Paths, symlinks, DNS answers, mutable identifiers, and approval state can change after verification. Minimize the gap or use an operation that binds checking and use.

## Lifecycle and evidence mistakes

**Equating PoP with replay prevention.** PoP binds a presentation to a holder and request. Rejecting a repeated presentation requires atomic nonce consumption; preventing duplicate effects requires idempotency or transactional deduplication.

**Treating a short TTL as revocation.** TTL limits future lifetime but cannot immediately invalidate authority. Revocation claims require current revocation state at every relevant verifier.

**Giving every child the same long lifetime and delegation depth.** Equal authority can be valid, but unused duration and delegation headroom increase exposure. Match TTL and terminal status to the delegated work.

**Assuming terminal prevents indirect use.** Terminal prevents further protocol delegation. The holder can still expose or exercise its existing authority through interfaces it controls.

**Treating approval as execution or exactly-once permission.** Approval authorizes the described request under its validation rules. It does not prove the action occurred, and without replay controls it does not necessarily authorize only one effect.

**Treating an authorization receipt as proof of the downstream result.** A receipt can evidence a decision. Proving execution or outcome requires evidence from the effecting system, preferably coupled transactionally.

## Operational mistakes

**Shipping development, observation, shadow, optional-warrant, or dry-run mode.** These modes are useful during adoption but provide a different guarantee. Make them explicit, time-bound, observable, and impossible to mistake for enforcement.

**Logging secrets or policy-sensitive arguments.** Avoid recording private keys, complete warrants, approvals, unrestricted tool arguments, or detailed denial predicates in caller-visible errors. Use stable references and protected diagnostics.

**Claiming complete mediation from happy-path tests.** A passing allowed call proves little about bypasses. Denial tests must show the effect was not invoked across direct, batch, retry, streaming, background, administrative, and concurrent paths relevant to the application.
