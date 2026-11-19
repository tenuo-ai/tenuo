# Versioned MCP Authorization Envelope

- Status: **Draft design proposal**
- Target: **Tenuo 0.4.0**
- Scope: `_meta.tenuo` framing and its proof-of-possession domain

This document proposes an explicitly versioned `_meta.tenuo` envelope for MCP
tool calls. It is intentionally a design document, not a statement of shipped
behavior. Normative words such as MUST describe the proposed v2 contract.

## 1. Summary

Tenuo 0.3.2 centralizes `_meta.tenuo` encoding and argument canonicalization in
the Rust core, but the envelope itself contains no version:

```json
{
  "warrant": "<base64 warrant stack>",
  "signature": "<base64 holder proof>",
  "approvals": ["<base64 approval>"]
}
```

The signature uses the existing `tenuo-pop-v1` domain. A verifier therefore
cannot distinguish an unsupported proof format from tampering, corruption, or
use of the wrong holder key. This is especially difficult to operate when a
canonicalization rule changes across releases.

Version 2 adds an explicit integer and a matching cryptographic domain:

```json
{
  "version": 2,
  "warrant": "<base64 warrant stack>",
  "signature": "<base64 holder proof>",
  "approvals": ["<base64 approval>"]
}
```

The v2 holder proof uses `tenuo-pop-v2`. Changing or removing `version` selects
a different proof domain and therefore invalidates the signature. New servers
can accept both the unversioned 0.3.2 format and v2 during a migration window,
then disable the legacy format deliberately.

## 2. Motivation

The v0.3.1 to v0.3.2 transition exposed two different concerns:

1. The argument canonicalization rules needed correction. Version 0.3.2 keeps
   JSON null in the signed map and treats an integral JSON number consistently
   across Rust, Python, and TypeScript.
2. The envelope had no machine-readable way to identify the proof rules. A
   mixed deployment could only report `invalid_pop`, even when the real cause
   was version skew.

The first concern is fixed in 0.3.2. This proposal addresses the second for
future changes. It does **not** add compatibility with 0.3.1 null-stripping or
its earlier numeric behavior.

## 3. Goals

- Make the envelope and proof format explicit before another canonicalization
  change is needed.
- Bind the selected version cryptographically, preventing downgrade by editing
  the JSON envelope.
- Permit a server-first rolling migration from the unversioned 0.3.2 format.
- Return a distinct, stable error for an unsupported or disabled version.
- Keep warrant, approval, receipt, and revocation wire formats unchanged.
- Keep authorization decisions in the Rust core for every SDK.
- Preserve fail-closed behavior for malformed, unknown, or disabled formats.
- Define byte-exact, cross-language conformance vectors.

## 4. Non-goals

- Restoring proof compatibility with 0.3.1.
- Negotiating weaker canonicalization after verification fails.
- Trying multiple proof algorithms in response to `invalid_pop`.
- Changing the warrant-stack or signed-approval encoding.
- Versioning the outer MCP protocol or arbitrary `_meta` fields owned by other
  applications.
- Providing general cryptographic algorithm negotiation. A future envelope
  version may introduce that separately.

## 5. Terminology

**Legacy envelope (v1)**
: The unversioned `_meta.tenuo` object emitted by Tenuo 0.3.2. Its proof domain
  is `tenuo-pop-v1`. Absence of `version` identifies this format.

**Versioned envelope (v2)**
: The object defined here, with `"version": 2` and proof domain
  `tenuo-pop-v2`.

**Envelope version**
: The complete contract for parsing the `_meta.tenuo` object, canonicalizing
  tool arguments, constructing the proof challenge, and mapping errors. It is
  not the warrant wire-format version.

## 6. Proposed wire format

### 6.1 Location

The envelope remains at `params._meta.tenuo`. The gateway-safe
`params.arguments._tenuo` carrier, where supported, carries the identical
object. Middleware MUST remove authorization material before invoking a tool.

### 6.2 Fields

| Field | v1 | v2 | Type | Meaning |
|---|---|---|---|---|
| `version` | MUST be absent | REQUIRED, exactly `2` | JSON integer | Envelope and proof format |
| `warrant` | REQUIRED | REQUIRED | string | Encoded warrant stack |
| `signature` | REQUIRED | REQUIRED | string | 64-byte holder proof, encoded |
| `approvals` | optional | optional | array of strings | Encoded signed approvals |

`approvals` MAY be absent or an empty array. V2 MUST NOT encode it as `null`.
The v1 reader retains the 0.3.2 compatibility behavior for an absent, empty,
or null `approvals` field.

`version` MUST be a JSON integer. Strings, booleans, null, fractional numbers,
and values outside the implementation's supported integer range are malformed.
Implementations MUST compare the integer value, not coerce it.

### 6.3 Unknown fields

V2 decoders MUST reject unknown fields inside `_meta.tenuo`. Silent acceptance
would allow two implementations to disagree about security-relevant envelope
metadata. Extensions require a new envelope version or a future, explicitly
specified extension container.

This rule does not restrict sibling fields in the outer MCP `_meta` object.

### 6.4 Encoding

The v2 encoding rules for `warrant`, `signature`, and `approvals` are the same
as the canonical 0.3.2 rules:

- Producers use padded standard base64.
- Readers may retain the documented legacy decoding allowances where required
  for existing artifacts.
- Existing size and count limits apply before base64 or CBOR decoding.

The JSON member order is not significant. Duplicate JSON member names MUST be
rejected wherever the original JSON text remains available.

## 7. Proof construction

### 7.1 Argument canonicalization

V2 initially adopts the 0.3.2 argument rules unchanged:

- Arguments are a JSON object.
- JSON null remains present in the signed value, including inside lists and
  nested objects.
- `1` and `1.0` produce the same integral constraint value when exactly
  representable as an `i64`.
- Fractional numbers preserve their IEEE-754 value.
- Object keys are unique and strings.
- The bounded-parser limits are enforced before signing or verification.
- The canonical argument map is ordered lexicographically for proof encoding.

Starting v2 with already-deployed 0.3.2 canonicalization keeps this proposal
focused on explicit versioning. A later change to any rule above requires a new
envelope/proof version.

### 7.2 Domain separation

The proof challenge keeps the existing structure:

```text
PopChallenge = (warrant_id, tool, sorted_args, timestamp_window)
```

The preimage domain changes with the envelope version:

```text
v1_preimage = b"tenuo-pop-v1" || deterministic_cbor(PopChallenge)
v2_preimage = b"tenuo-pop-v2" || deterministic_cbor(PopChallenge)
```

The signature operation's existing outer signature context remains unchanged.
The v2 domain MUST be selected only by a parsed `version: 2` envelope.

Although `version` is not repeated inside `PopChallenge`, it is
cryptographically bound by selecting a distinct domain. Rewriting or removing
the field makes the verifier construct a different preimage.

### 7.3 No verification fallback

A verifier MUST NOT retry another version after a signature failure. It first
parses the envelope version, selects exactly one proof algorithm, and verifies
once under that contract. This prevents a malformed or tampered proof from
silently entering a weaker compatibility path.

## 8. Verification algorithm

Proposed high-level behavior:

```text
verify_envelope(meta, tool, argument_json, policy):
    require meta is an object

    if "version" is absent:
        if policy.accept_legacy_v1 is false:
            return legacy_envelope_disabled
        format = v1
    else:
        require version is an integer
        if version != 2:
            return unsupported_envelope_version
        format = v2

    validate exactly the fields allowed by format
    enforce encoded-field bounds
    decode warrant stack, proof, and approvals
    canonicalize arguments according to format
    verify the holder proof in format's domain

    if proof verification fails:
        return invalid_pop

    continue with chain, trust, expiry, replay, approval, and constraint checks
```

Version selection occurs before decoding large fields or performing
cryptographic work. Unknown and disabled versions fail closed.

## 9. Error model

The transport-facing categories should distinguish framing compatibility from
cryptographic failure:

| Code | Meaning |
|---|---|
| `unsupported_envelope_version` | A syntactically valid integer version is not supported |
| `legacy_envelope_disabled` | The envelope has no version and v1 acceptance is disabled |
| `malformed_envelope` | `version` has the wrong JSON type or the envelope violates its schema |
| `invalid_arguments` | Argument JSON is malformed or cannot be canonicalized |
| `payload_too_large` | An envelope or argument resource bound is exceeded |
| `invalid_pop` | The proof is well-formed but invalid under the selected version |

Remote errors SHOULD expose the stable code but MUST NOT include signatures,
keys, warrants, approval tokens, or argument values. Audit events SHOULD record
the selected envelope version and whether a legacy policy path was used.

## 10. Migration from 0.3.2

### 10.1 Compatibility properties

- A 0.4 server in compatibility mode accepts an unversioned 0.3.2 envelope as
  v1.
- A 0.4 server accepts a v2 envelope.
- A 0.3.2 server does not understand the v2 proof domain and rejects a v2
  signature. This is fail-closed behavior.
- A 0.4 client can emit legacy v1 only when explicitly configured to do so.
- No 0.4 component implements the 0.3.1 null-stripping proof rules.

### 10.2 Deployment sequence

1. Upgrade all verifiers and servers to 0.4 with legacy-v1 acceptance enabled.
2. Confirm they report support for v2 and observe the version metric.
3. Upgrade clients and holders to emit v2.
4. Wait until legacy-v1 traffic reaches zero for the required rollback window.
5. Disable legacy-v1 acceptance by policy.
6. Remove legacy-v1 support only in a later, separately announced release.

Clients MUST NOT begin emitting v2 before their destination verifiers support
it unless the deployment intentionally accepts a fail-closed outage.

### 10.3 Configuration

The implementation should expose an explicit verifier policy rather than an
environment-dependent fallback:

```text
accept_legacy_v1: true | false
```

The 0.4 default is proposed to be `true` for servers and verifiers. New clients
default to emitting v2, with an explicit temporary option to emit legacy v1.
The legacy emission option should log or surface a deprecation signal without
including call arguments.

## 11. Capability discovery

MCP initialization offers a possible place for a server to advertise supported
Tenuo envelope versions. This proposal does not require negotiation for basic
correctness: deployments can upgrade servers first and configure clients.

Before implementation, choose one of these approaches:

1. **Configuration only:** simplest and usable through gateways that do not
   preserve MCP initialization metadata.
2. **Advisory MCP capability:** advertise supported versions, but require an
   explicit client policy when no capability is visible.
3. **Mandatory negotiation:** safest for direct MCP connections but adds state
   and may not work through every adapter or gateway.

Regardless of discovery, clients MUST NOT silently downgrade after a v2 proof
is rejected.

## 12. Security considerations

### 12.1 Downgrade resistance

Changing `version: 2` to another value, or removing it, selects a different
proof domain. The original signature therefore fails. A verifier never retries
v2 after selecting v1 or vice versa.

### 12.2 Fail-closed unknown versions

An unknown version is not `invalid_pop`; it is rejected before proof checking
as `unsupported_envelope_version`. A verifier MUST NOT interpret an unknown
version using its newest or oldest known rules.

### 12.3 Legacy policy is explicit

Unversioned v1 acceptance is a deployment policy, not an automatic recovery
path. Operators can observe and disable it. The policy affects only the 0.3.2
format; it does not enable 0.3.1 canonicalization.

### 12.4 Intermediaries

Gateways and middleware MUST forward the complete `_meta.tenuo` object without
rewriting `version`, and MUST remove it before tool execution. Systems using
the `_tenuo` argument carrier apply the same requirement before schema
validation and handler invocation.

### 12.5 Parser agreement

Rust is the authoritative envelope parser and proof implementation. Python and
TypeScript pass host values or JSON text into that implementation rather than
reimplementing version selection, canonicalization, or domain selection.

## 13. Test and release requirements

Implementation is not complete until all of the following exist:

- Byte-exact v1 and v2 vectors generated from fixed keys and timestamps.
- Rust, Python, and TypeScript tests consuming the same vectors.
- Tests proving that editing, removing, or changing `version` invalidates v2.
- Tests proving that a verifier never falls back after `invalid_pop`.
- Tests for wrong JSON types, unknown versions, duplicate fields, unknown
  fields, oversized fields, and excessive approval counts.
- Tests covering null at every nesting depth, integral and fractional numbers,
  Unicode, key ordering, and boundary resource limits under both formats.
- A published-0.3.2-client to 0.4-server compatibility lane.
- A 0.4-client to published-0.3.2-server expected-denial lane.
- Server-first rolling-upgrade and legacy-disable integration tests.
- Property tests showing that a v1 proof never verifies in the v2 domain and a
  v2 proof never verifies in the v1 domain.
- Fuzz coverage for version parsing and envelope field validation.
- Release notes that identify the deployment order and rollback boundary.

## 14. Proposed implementation shape

The core API should make the selected format explicit rather than pass a loose
integer through security-sensitive code:

```rust
enum MetaEnvelopeVersion {
    LegacyV1,
    V2,
}

struct TenuoMeta {
    version: MetaEnvelopeVersion,
    warrant: String,
    signature: String,
    approvals: Vec<String>,
}
```

Signing should default to v2 only at the public 0.4 client boundary. Internal
functions should require a `MetaEnvelopeVersion` argument so tests and
migration code cannot accidentally depend on an implicit default.

Decoding should return the selected version alongside the decoded artifacts.
The guard/verifier must use that value when constructing the PoP preimage.
Python and WASM bindings should expose stable version and error values, not
duplicate the parsing rules.

## 15. Open design decisions

The draft PR should resolve these before implementation begins:

1. Should v2 reject all unknown fields, as proposed, or define an explicit
   extension map now?
2. Should MCP capability advertisement be advisory, mandatory, or deferred?
3. How long should servers accept unversioned v1 by default?
4. Should the temporary client `emit_legacy_v1` option exist in every SDK or
   only at low-level transport APIs?
5. Should `unsupported_envelope_version` include the received integer in local
   diagnostics while keeping remote messages minimal?
6. Does the gateway HTTP transport need the same versioned envelope contract,
   or should this proposal remain MCP-specific until that transport carries an
   equivalent object?
7. Should the v2 deterministic CBOR challenge include the integer version in
   addition to the `tenuo-pop-v2` domain for defense in depth and easier vector
   inspection?

## 16. Decision record

| Decision | Status | Rationale |
|---|---|---|
| Target 0.4.0 | Proposed | Versioning is a protocol lifecycle feature, not a 0.3.2 hot fix |
| Unversioned means 0.3.2/v1 | Proposed | Enables server-first migration without changing deployed clients |
| Do not support 0.3.1 canonicalization | Proposed | Avoids restoring null-stripping and ambiguous proof semantics |
| Use `version: 2` plus `tenuo-pop-v2` | Proposed | Human-readable framing plus cryptographic downgrade resistance |
| Keep 0.3.2 canonicalization in v2 | Proposed | Separates lifecycle work from another argument-semantics change |
| Reject unknown v2 fields | Proposed | Prevents silent parser disagreement about security metadata |
| Never retry another version after proof failure | Proposed | Preserves fail-closed behavior and prevents downgrade fallback |
