# Framework-neutral integration

Use this reference when a project has no official Tenuo adapter or verified framework recipe. The goal is to apply the protocol at a reliable extension point without implying official framework support.

## Classify the result

Use one of these labels in the implementation summary:

| Label | Required evidence |
| --- | --- |
| Official adapter | Published and maintained by Tenuo with compatibility tests for the named framework versions |
| Verified recipe | Repository example exercised by CI against the named framework version or range |
| Generic integration | Project-specific use of supported core APIs with local conformance tests |
| Unsupported | No reliable pre-effect interception point, argument mapping, or authority transport was established |

Never promote a generic integration to an official adapter by wording alone.

## Find the extension point

Inspect the framework for the first reliable option in this order:

1. Server-side middleware or an interceptor that runs before every protected handler.
2. A single tool-execution callback through which every protected call passes.
3. A remote gateway, worker, or service handler that can verify before the effect.
4. A wrapper around each effecting function, only when bypass routes can be removed or the weaker in-process threat model is acceptable.

Determine whether the hook exposes the final tool name, all material arguments, request metadata, errors, retries, streaming behavior, and cancellation. Trace direct SDK calls, background jobs, queues, administrative paths, and fallback execution separately.

If no hook can run before the effect with the final material arguments, classify the framework path as unsupported and recommend moving enforcement to a gateway or service boundary. Do not insert a post-execution audit hook and call it authorization.

## Adapter contract

A generic adapter must establish all of these behaviors:

- It accepts authority and holder proof through an authenticated or integrity-protected transport location appropriate to the framework.
- It derives a stable capability name from the actual handler selected by the framework.
- It extracts every argument that materially changes the effect, including defaults inserted by the framework.
- It normalizes each value once at the trusted boundary and uses that same representation for verification and execution.
- It calls a supported Tenuo verification API with independently provisioned trusted roots.
- It invokes the effect only after an allow decision and passes the verified arguments forward.
- It maps denial to a terminal framework outcome that does not trigger an unprotected fallback.
- It preserves cancellation and retry semantics without reusing authority beyond the intended operation.
- It consumes a nonce or uses effect-level idempotency when replay or duplicate execution matters.
- It emits only non-sensitive diagnostic context and does not log warrants, private keys, approval artifacts, or unrestricted arguments by default.

Keep issuance and verification separable. A server should not trust a new root merely because the request that carries a warrant also supplies it.

## Conformance checklist

Build a harness around the framework hook with a fake effect and an invocation record. The harness passes only when it demonstrates:

- allowed authority invokes the effect once with the verified arguments;
- missing authority invokes it zero times;
- malformed and expired authority invoke it zero times;
- an untrusted issuer invokes it zero times;
- the wrong holder proof invokes it zero times when warrants and PoP are used;
- a wrong capability and every material constraint violation invoke it zero times;
- framework-supplied default arguments are included in the authorization decision;
- an authorization exception, timeout, cancellation, or stream failure cannot fall through to execution;
- direct, batch, streaming, retry, background, and administrative paths either pass through the hook or are documented as residual bypasses;
- a wider delegated child is rejected before transport or execution;
- duplicate presentation is rejected or produces one effect when one-use behavior is claimed;
- concurrent requests cannot borrow another request's authority;
- denial details returned to an untrusted caller do not disclose policy or secret material.

Use stable error codes and effect records in assertions rather than matching incidental error prose.

## Completion threshold

A generic integration is ready to present when the hook, transport, argument mapping, and deny-before-effect tests are all concrete. If any is missing, provide a partial implementation only when the user asked for one and state which security property remains unestablished.
