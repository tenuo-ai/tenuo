---
title: Attenuating Authorization Tokens for Agentic Delegation Chains
abbrev: Attenuating Agent Tokens
docname: draft-niyikiza-oauth-attenuating-agent-tokens-01
category: std
consensus: true
submissiontype: IETF
ipr: trust200902
date: 2026-03-16
area: Security
workgroup: Web Authorization Protocol (OAuth)

author:
  - fullname: Niki Aimable Niyikiza
    organization: Tenuo
    email: niki@tenuo.ai

normative:
  RFC3986:   # Uniform Resource Identifier (URI): Generic Syntax
  RFC7515:   # JWS
  RFC7517:   # JWK
  RFC7519:   # JWT
  RFC7638:   # JWK Thumbprint
  RFC7800:   # Proof-of-Possession Key Semantics for JWTs
  RFC8032:   # EdDSA
  RFC8785:   # JSON Canonicalization Scheme (JCS)
  RFC9278:   # JWK Thumbprint URI
  RFC9396:   # Rich Authorization Requests
  RFC9562:   # Universally Unique IDentifiers (UUIDs)
  RFC6749:   # OAuth 2.0 Authorization Framework
  RFC9201:   # OAuth Parameters for ACE

informative:
  RFC8414:   # OAuth 2.0 Authorization Server Metadata
  RFC8126:   # Guidelines for Writing an IANA Considerations Section
  RFC8949:   # Concise Binary Object Representation (CBOR)
  RFC8392:   # CBOR Web Token (CWT)
  RFC8693:   # OAuth 2.0 Token Exchange
  RFC9052:   # CBOR Object Signing and Encryption (COSE)
  RFC9449:   # DPoP
  BISCUIT:
    title: "Biscuit: Distributed Authorization Tokens"
    target: https://doc.biscuitsec.org/reference/specifications.html
    author:
      - org: Eclipse Foundation
  CEDAR:
    title: "Cedar Policy Language Reference Guide"
    target: https://docs.cedarpolicy.com/
    author:
      - org: Cedar Policy
  MACAROONS:
    title: "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"
    author:
      - name: Arnar Birgisson
      - name: Joe Gibbs Politz
      - name: Ulfar Erlingsson
      - name: Ankur Taly
      - name: Michael Vrable
      - name: Mark Lentczner
    date: 2014
    seriesinfo:
      NDSS: "2014"
    target: https://research.google/pubs/pub41892/
  SALTZER75:
    title: "The Protection of Information in Computer Systems"
    author:
      - name: Jerome H. Saltzer
      - name: Michael D. Schroeder
    date: 1975
    seriesinfo:
      Proceedings of the IEEE: "Vol. 63, No. 9"
    target: https://doi.org/10.1109/PROC.1975.9939
  HARDY88:
    title: "The Confused Deputy (or why capabilities might have been invented)"
    author:
      - name: Norm Hardy
    date: 1988
    seriesinfo:
      ACM SIGOPS Operating Systems Review: "Vol. 22, No. 4"
    target: https://dl.acm.org/doi/10.1145/54289.871709
  CAMEL25:
    title: "Defeating Prompt Injections by Design"
    author:
      - name: Edoardo Debenedetti
      - name: Ilia Shumailov
      - name: Tianqi Fan
      - name: Jamie Hayes
      - name: Nicholas Carlini
      - name: Daniel Fabian
      - name: Christoph Kern
      - name: Chongyang Shi
      - name: Andreas Terzis
      - name: Florian Tramèr
    date: 2025
    target: https://arxiv.org/abs/2503.18813
  DEEPMIND26:
    title: "Intelligent AI Delegation"
    author:
      - name: Nenad Tomašev
      - name: Matija Franklin
      - name: Simon Osindero
    date: 2026
    target: https://arxiv.org/abs/2602.11865
  WIMSE-ARCH:
    title: "Workload Identity in a Multi System Environment (WIMSE) Architecture"
    author:
      - name: Joe Salowey
      - name: Yaroslav Rosomakho
      - name: Hannes Tschofenig
    date: 2026-03
    target: https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
  WIMSE-S2S:
    title: "WIMSE Workload-to-Workload Authentication"
    author:
      - name: Brian Campbell
      - name: Joseph A. Salowey
      - name: Arndt Schwenkschuster
      - name: Yaron Sheffer
    date: 2025-10
    target: https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/
  DENNIS66:
    title: "Programming Semantics for Multiprogrammed Computations"
    author:
      - name: Jack B. Dennis
        ins: J. B. Dennis
      - name: Earl C. Van Horn
        ins: E. C. Van Horn
    date: 1966
    seriesinfo:
      "Communications of the ACM": "Vol. 9, No. 3"
    target: https://doi.org/10.1145/365230.365252
  MILLER06:
    title: "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control"
    author:
      - name: Mark S. Miller
        ins: M. S. Miller
    date: 2006
    seriesinfo:
      "PhD Dissertation": "Johns Hopkins University"
    target: http://www.erights.org/talks/thesis/
  ALLOY:
    title: "Alloy: A Lightweight Object Modelling Notation"
    author:
      - name: Daniel Jackson
    date: 2002
    seriesinfo:
      "ACM Transactions on Software Engineering and Methodology": "Vol. 11, No. 2"
    target: https://doi.org/10.1145/505145.505149
  Z3:
    title: "Z3: An Efficient SMT Solver"
    author:
      - name: Leonardo de Moura
        ins: L. de Moura
      - name: Nikolaj Bjørner
        ins: N. Bjørner
    date: 2008
    seriesinfo:
      "TACAS 2008, LNCS": "4963"
    target: https://github.com/Z3Prover/z3
---

This document defines Attenuating Authorization Tokens (AATs), a
signed credential format for secure delegation in AI agent systems.
An AAT encodes which tools an agent may invoke and with what
argument constraints. Any holder can derive a more restrictive token offline
that narrows or maintains scope but cannot expand it. This
invariant is cryptographically enforced and verifiable offline by
any party holding the root token's trust anchor key.

This specification extends the Rich Authorization Requests format
(RFC 9396) with delegation-chain semantics and defines a typed
constraint vocabulary for tool-level argument restrictions. The
accompanying chain verification algorithm enforces the monotonic
attenuation invariant at each delegation step and requires no network
contact with the root issuer.

--- middle

# Introduction

AI agent systems increasingly delegate tasks to chains of autonomous
agents, each invoking tools on behalf of a user or service. Today,
the tokens that authorize these invocations are typically scoped to
the principal — the user or service account — not to the task the
agent is performing. Even when an OAuth scope narrows the token to a
subset of APIs, it does not express which tools, with which argument
values, a particular agent should use for a particular task. The
token that checks flight availability also authorizes completing a
purchase and charging a corporate card. A prompt injection attack, a
model hallucination, or a compromised sub-agent can exploit this
gap, exercising authority the agent should never have needed. This
is the confused deputy problem {{HARDY88}} applied to agentic
delegation.

This problem is compounded by a gap in existing infrastructure. The
WIMSE architecture {{WIMSE-ARCH}} provides mechanisms for
establishing workload identity and propagating it across service
boundaries. OAuth 2.0 {{RFC6749}} provides token issuance and
scoping. Neither provides a mechanism for a token holder to derive a
narrower token and pass it downstream. Without delegation-aware
semantics, the only options are to trust every agent in the chain
with the full token or to require each delegation step to contact
the authorization server. The latter is impractical for agentic
workflows that execute tool invocations in rapid succession, operate
across trust boundaries, or run in environments with intermittent
connectivity.

Capability-based systems {{DENNIS66}} solve both problems. Authority
is carried by unforgeable tokens scoped to specific operations; a
holder can attenuate a capability before passing it on, but cannot
amplify it {{SALTZER75}}. This document defines such a mechanism for
OAuth-based agent systems, complementing WIMSE's identity layer with
a delegation and attenuation layer. The resulting chain lets
enforcement points evaluate both the leaf token and the delegation path
that produced it.

The following diagram shows the delegation flow this specification
enables:

~~~
Root Issuer
       |
       | issues root AAT (Section 3.7)
       v
Orchestrating Agent
       |
       | derives AAT (Section 6)
       v
Planning Agent
       |
       | derives AAT (Section 6)
       v
Tool-Invoking Agent
       |
       | presents AAT with PoP JWT (Section 5)
       v
Enforcement Point
  (verifies chain offline, Section 7)
~~~

At each derivation step, the derived token's scope is a subset of
the parent's: scope can only narrow or stay the same, never widen. The
enforcement point verifies the complete chain using only the root
token's trust anchor key; no network calls are required. How token
chains are carried to enforcement points is deployment-specific; this
document does not define a transport binding.

## Limitations of Existing OAuth Mechanisms for Agentic Delegation

OAuth 2.0 Token Exchange {{RFC8693}} enables a principal to obtain a new
token with reduced scope by contacting the authorization server. The
server enforces the scope reduction. This requires a synchronous
round-trip to the authorization server at each delegation hop. In
multi-agent chains, this makes the authorization server a participant in
every delegation decision, coupling the delegation topology to
authorization server (AS) availability. {{RFC8693}} supports
representing prior delegation actors via nested `act` claims, but those
claims are informational for access control decisions rather than a
cryptographically self-verifiable attenuation chain. The AS mediates
each grant independently, and no mechanism ensures that downstream
delegation intent remains consistent with the original authorization
scope.

Rich Authorization Requests (RAR) {{RFC9396}} extend OAuth tokens with
structured authorization detail objects, enabling expressive capability
descriptions. RAR addresses the expressiveness problem. It does not
define how a token holder can produce a narrower token, or how a
chain of such derivations can be verified.

Proposals to extend the authorization code flow with explicit agent
consent, such as introducing a `requested_actor` parameter at the
authorization endpoint, address who the agent is and whether the
user approved the delegation. They do not constrain which tools the
agent may invoke or with what argument values. AATs are
complementary: they scope authority to specific tools and arguments
after identity and consent have been established.

To the author's knowledge, no existing OAuth standard defines a
delegation chain protocol with a cryptographically enforced attenuation
invariant and offline chain verification.

## Design Goals

1. **Least privilege at the invocation boundary.** An agent's
   authorization token encodes which tools it may call and with what
   argument constraints, scoped to the task, not to the full authority
   of the calling principal.

2. **Offline derivation.** A token holder can derive a more restrictive
   token without contacting the root issuer.

3. **Independent chain verification.** Any enforcement point holding
   the trust anchor can verify the complete delegation chain without
   network calls.

4. **Cryptographically enforced attenuation.** A derived token cannot
   grant broader authority than its parent.

5. **JWT/JWS interoperability.** The primary encoding specified by this
   document is a signed JWT {{RFC7519}} using JWS {{RFC7515}},
   allowing deployments to verify chains using existing JSON Object
   Signing and Encryption (JOSE) infrastructure without new
   cryptographic dependencies.

## Relationship to Prior Work

Macaroons {{MACAROONS}} introduced the concept of attenuating tokens
with contextual caveats. Macaroons use HMAC chaining, which provides
attenuation but not proof of possession, and express caveats as
free-form predicates evaluated at the target service at runtime. This
specification adds asymmetric proof of possession, structured
tool-level capability claims, and a typed constraint vocabulary.
It defines a normative subsumption relation, enabling any party
holding the chain to verify monotonicity structurally, without
predicate evaluation at a central service.

Biscuit {{BISCUIT}} extends the Macaroons model with asymmetric public
key signatures and offline attenuation, addressing the
proof-of-possession gap. Biscuit expresses authorization policies in a
Datalog variant, requiring a logic engine at verification time. This
specification uses structured constraint types decidable by structural
analysis and defines an explicit delegation-chain model with
chain-position claims and attenuation invariants. A detailed comparison
appears in Appendix A.

The capability-based security model underlying AATs draws on
{{DENNIS66}}, which introduced capabilities as unforgeable tokens of
authority, and {{MILLER06}}, which formalized the principle of least
authority (POLA) and the attenuation property in object-capability
systems. AATs apply these principles at the protocol layer: each token
is a capability scoped to specific tools and arguments, and derivation
can only attenuate, never amplify, the authority it carries.

{{DEEPMIND26}} argues that safe multi-agent delegation requires explicit
transfer of authority, responsibility, and trust at each delegation
step, with bounded operational scope. {{CAMEL25}} shows that
capability-based controls enforced at the tool boundary can provide
provable security properties in an agentic framework. These results
motivate a protocol-layer mechanism that encodes delegation scope in
verifiable credential artifacts enforced independently of model
behavior. AATs realize one protocol-layer approach to that goal.


# Terminology

{::boilerplate bcp14-tagged}

**Attenuating Authorization Token (AAT):** A signed credential as defined
in this document. The fully specified encoding in this document is a
signed JWT. An AAT encodes tool-level capability claims and supports
offline derivation of derived tokens with authority equal to or narrower
than the parent's.

**Root Token:** An AAT with no parent token, `del_depth: 0`, and
`par_hash` absent. A root token is signed by the private key
corresponding to a trust anchor and establishes the authority ceiling for
all derived tokens. A root token is a chain position, not a distinct
token type.

**Root Issuer:** The entity that mints root tokens. The root issuer
holds the private key corresponding to a trust anchor and is responsible
for verifying agent identity and requested authority before issuance.

**Token Holder:** The entity that possesses an AAT and the private key
corresponding to its `cnf.jwk` claim. The token holder is the party
authorized to derive further tokens from it, subject to the chain's depth
limits. The holder of the leaf token is also the party authorized to
present the chain for tool invocation by signing the PoP JWT.

**Derived Token:** An AAT produced by a token holder from a parent AAT,
also referred to as a child token. A derived token's authority is a
subset of its parent's authority (equal or narrower). Derivation does
not require a round-trip to the root issuer.

**Tool:** An addressable function or API operation that an agent may
invoke. A tool is identified by a string identifier. Tool identifiers
SHOULD be URIs ({{RFC3986}}); see Section 3.3.1 for requirements. Tool
identifiers MUST NOT contain characters that are subject to Unicode
normalization (such as combining characters or characters with multiple
canonical forms), as normalization-sensitive identifiers can produce
inconsistent matching behavior across implementations.

**Argument Constraint:** A predicate over a tool argument value that the
argument MUST satisfy for the invocation to be authorized. Constraints
are evaluated at the enforcement point before invocation.

**Capability Claim:** The set of (tool, argument constraints) pairs
encoded in an AAT's `authorization_details` claim.

**Attenuation:** The process of deriving a token with a capability
claim that is a subset of the parent token's capability claim.
Attenuation is the only permitted direction of derivation.

**Chain:** An ordered sequence of AATs from root to leaf, where each
token was derived from its predecessor.

**Leaf Token:** The last token in a chain. The leaf token is the one
presented to the enforcement point for authorization. The PoP JWT is
signed by the private key corresponding to the leaf token's `cnf.jwk`.

**Enforcement Point:** The component that receives a tool
invocation request, verifies the presented token chain, evaluates
argument constraints, and permits or denies execution.

**Trust Anchor:** A public key that enforcement points are configured to
trust as the root of a delegation chain. Root tokens are signed by the
private key corresponding to a trust anchor.

**Proof of Possession (PoP):** A cryptographic demonstration that the
presenter of a token controls the private key corresponding to the
public key bound in the token's `cnf` claim. In this specification, the
token holder presents the chain and signs the PoP JWT using the same
private key.


# Token Structure

## Chain Position and Invocation Semantics

This specification does not define separate token types for delegation
and execution. An AAT's role is determined by its position in the
presented chain.

The root token establishes the authority ceiling. Intermediate tokens
record attenuations made by holders along the delegation path. The leaf
token is the token whose holder presents a PoP JWT and whose capability
claims are evaluated against the requested tool invocation.

A holder of any AAT MAY derive a child token when `del_depth` is strictly
less than `del_max_depth`. The derived token MUST carry authority equal
to or narrower than the parent token, as enforced by the capability
monotonicity invariant (I4, Section 4.5). A token MUST NOT be accepted
for a tool invocation except as the leaf of a successfully verified
chain.

## Common Claims

The following claims appear in all AATs. All claims listed as
REQUIRED MUST be present. Claims listed as OPTIONAL MAY be omitted;
their absence carries the semantics described in the table.

| Claim | Type | Required | Description |
|---|---|---|---|
| `jti` | string | REQUIRED | Unique token identifier. SHOULD be a UUIDv7 value. When a UUID is used, it MUST be encoded as a lowercase hyphenated string in the form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` per {{RFC9562}}. |
| `iss` | string | REQUIRED | Identifier of the entity that signed this token. For root tokens, MUST be a URI identifying the root issuer. For derived tokens, MUST be a JWK Thumbprint URI as defined in {{RFC9278}}, using the SHA-256 hash algorithm: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>`, where `<thumbprint>` is computed per {{RFC7638}}. |
| `iat` | NumericDate | REQUIRED | Time at which the token was issued. MUST NOT be more than MAX_IAT_SKEW in the future relative to the enforcement point's clock (see Section 4.4). In a chain, a derived token's `iat` MUST NOT be earlier than its parent's `iat`. |
| `exp` | NumericDate | REQUIRED | Time at which the token expires. MUST be greater than `iat`. MUST NOT exceed `iat` plus MAX_TOKEN_LIFETIME (see Section 4.4). |
| `cnf` | object | REQUIRED | Confirmation claim {{RFC7800}}. MUST contain `jwk` with the holder's public key. The `jwk` value MUST be a public key; private key material MUST NOT appear in this field. |
| `del_depth` | integer | REQUIRED | Delegation depth. 0 for root tokens. Incremented by exactly 1 at each derivation step (see Section 4.3). |
| `del_max_depth` | integer | REQUIRED | Maximum delegation depth permitted in this chain. MUST be a non-negative integer not exceeding the implementation's MAX_DELEGATION_DEPTH (Section 4.3). |
| `par_hash` | string | MUST (derived) / MUST NOT (root) | Base64url-encoded SHA-256 digest of the parent token signing input, using base64url encoding without padding as defined in {{RFC7515}} Appendix C. For JWT/JWS AATs, the parent token signing input is the JWS Signing Input. MUST be absent in root tokens. MUST be present in all derived tokens. |
| `authorization_details` | array | REQUIRED | Tool capability claims. Format defined in Section 3.3. |

Implementations MUST support Ed25519 {{RFC8032}} for token signing and
verification. Implementations MAY support additional algorithms.

In both root and derived tokens, `iss` is a URI. For root tokens,
`iss` is a URI identifying the root issuer, consistent with
conventional OAuth usage. For derived tokens, `iss` is a JWK
Thumbprint URI {{RFC9278}} that encodes the SHA-256 thumbprint of
the signing key. This makes I1 verifiable offline: the enforcement
point can confirm that the thumbprint embedded in `derived.iss`
matches `parent.cnf.jwk` without any external lookup.

This specification intentionally omits the `sub` claim. In conventional
OAuth tokens, `sub` identifies the resource owner or principal on whose
behalf the token is issued. In an AAT chain, the holder's identity is
fully determined by `cnf.jwk`: the entity presenting the token proves
possession of the private key corresponding to `cnf.jwk`. Including a
`sub` claim would introduce an additional identity binding that is not
cryptographically enforced by this specification and could be set
arbitrarily by any delegating party. Implementations that require a
human-readable subject identifier MAY convey one in additional JWT
claims outside this specification (see Appendix B.7).

## Capability Claims via `authorization_details`

This specification profiles {{RFC9396}} for tool-level capability
claims. An AAT capability entry is an `authorization_details` entry
whose `type` is set to `"attenuating_agent_token"`. Such an entry MUST
include a `tools` member that maps tool names to argument constraint
sets.

~~~json
{
  "authorization_details": [
    {
      "type": "attenuating_agent_token",
      "tools": {
        "read_file": {
          "path": {
            "constraint_type": "one_of",
            "values": ["/data/q3-report.pdf", "/data/q4-report.pdf"]
          }
        },
        "search_index": {
          "query": {
            "constraint_type": "one_of",
            "values": ["public filings", "public releases"]
          },
          "limit": { "constraint_type": "range", "max": 100 }
        }
      }
    }
  ]
}
~~~

A tool entry with an empty constraint map `{}` is valid and indicates
that the tool is authorized without argument restrictions.

When a tool entry contains one or more argument constraints, the
enforcement point operates in closed-world mode for that tool
invocation: any argument not named in the constraint map MUST be
rejected. A constrained argument that is absent from the invocation MUST
also be rejected. The presence of a constraint asserts that the
issuer has reasoned about that argument. An invocation that omits
it has not been validated against that reasoning. This is a
security property, not a configuration option.

Issuers who wish to permit an argument to be omitted MUST NOT include a
constraint for it in the constraint map. There is no "optional
constraint" mechanism; the constraint map is a closed specification of
the required invocation shape. To authorize an argument without
restricting its value, use a `wildcard` constraint (see below).

A token issuer that wishes to allow unconstrained arguments alongside
constrained ones MUST explicitly include a `wildcard` constraint for
each argument that should be unrestricted. A `wildcard` constraint
satisfies closed-world mode while permitting any value for that argument
(see Section 3.4). Enforcement points MUST enforce closed-world mode and
MUST NOT permit unconstrained arguments when any constraint is present
for the tool (see Section 7, step 6b).

The `authorization_details` array MAY contain entries of other types
alongside `attenuating_agent_token` entries, consistent with the
extensibility model of {{RFC9396}}. Enforcement points implementing this
specification process only entries with `type` set to
`attenuating_agent_token` and MUST ignore entries of other types. An
`authorization_details` array containing multiple entries with `type:
"attenuating_agent_token"` is invalid; the tools map in a single entry
provides sufficient structure for all tool-level capability claims.

Root tokens and leaf tokens MUST contain exactly one entry with `type:
"attenuating_agent_token"`. Non-leaf derived tokens MAY contain zero
entries of this type, in which case they represent the empty capability
set and can only derive further empty-capability tokens. Such a non-leaf
derived token MAY carry an empty `authorization_details` array.

### Tool Identifier Requirements

Tool identifiers are the keys of the `tools` map in an
`authorization_details` entry. The following requirements apply.

Tool identifiers MUST be unique within the `tools` map of a single
token. An `authorization_details` entry containing duplicate tool
identifier keys is malformed and MUST be rejected.

Tool identifiers SHOULD be URIs ({{RFC3986}}). URI-format identifiers
provide namespace isolation across agents and prevent semantic collision
when multiple agents in a deployment expose tools with identical local
names.

When URI-format identifiers are used, the URI SHOULD be scoped to the
authority of the agent that exposes the tool. The authority component
SHOULD correspond to the agent's workload identity or a domain
controlled by the agent's operator. The URI SHOULD include a version
component or content hash to ensure that all parties in the chain reason
about the same tool schema. For example:

    https://billing-agent.example.com/tools/charge/v2

Tool identifiers that are not URIs MAY be used in single-agent
deployments where namespace collision is not a concern. Deployments
spanning multiple agents or trust domains SHOULD use URI-format
identifiers.

A tool identifier carries no inherent authorization semantics beyond
naming a capability. The root issuer is responsible for verifying that
the tool identifier is meaningful and that the requesting agent is
authorized to claim identifiers under the tool URI's authority component
before minting a root token (Section 3.7.3).

## Argument Constraints

Each argument constraint is an object with a `constraint_type` member
and type-specific members. The following constraint types are defined
normatively. The `check` predicate and `subsumes` relation for each type
are normative: two independent implementations MUST produce identical
results when evaluating either predicate against the same inputs.

The core constraint set is intentionally limited to constraint types
with simple, deterministic, format-independent `check` and `subsumes`
rules. Domain-specific matchers and policy-language constraints, such as
path containment, glob patterns, regular expressions, or authorization
policy expressions, are not core constraint types. To be used
interoperably in AAT `authorization_details`, they MUST be defined as
registered extension constraint types (Section 3.5). The registration
process confirms that the extension defines an unambiguous runtime
`check` predicate and a decidable, sound, and deterministic `subsumes`
procedure. Deployments requiring richer policy expressiveness SHOULD use
a registered extension constraint type (see Appendix C).

| `constraint_type` | Additional Members | Semantics |
|---|---|---|
| `exact` | `value` (any scalar) | Argument MUST equal `value` exactly. |
| `range` | `min` (number, optional), `max` (number, optional), `min_inclusive` (boolean, optional, default true), `max_inclusive` (boolean, optional, default true) | Argument MUST be a number satisfying the specified bounds. Both bounds are optional. `min_inclusive` and `max_inclusive` control whether the respective bound is included in the valid range; both default to true (closed interval). |
| `one_of` | `values` (array) | Argument MUST be a member of `values`. |
| `not_one_of` | `excluded` (array) | Argument MUST NOT be a member of `excluded`. |
| `contains` | `required` (array) | Argument, which MUST be an array, MUST contain every element listed in `required`. |
| `subset` | `allowed` (array) | Argument, which MUST be an array, MUST be a subset of `allowed`. |
| `wildcard` | (none) | Any value is accepted. |
| `all` | `constraints` (array) | Logical AND of nested constraints. See Section 4.5 for subsumption rules. |
| `any` | `constraints` (array) | Logical OR of nested constraints. See Section 4.5 for subsumption rules. |

Enforcement points MUST reject invocations where any argument violates
its associated constraint. Enforcement points MUST deny authorization if
they encounter a `constraint_type` they do not recognize (fail-closed
behavior). This fail-closed rule applies only to constraint types within
`authorization_details`. Enforcement points MUST ignore unrecognized
top-level JWT claims; a token MUST NOT be rejected solely because it
contains claims outside those defined in this specification.

Composite constraint types (`all`, `any`) are recursive.
MAX_CONSTRAINT_DEPTH is an implementation-defined finite integer
specifying the maximum nesting depth of a constraint tree.
Implementations MUST enforce a finite MAX_CONSTRAINT_DEPTH to prevent
resource exhaustion from pathologically deep constraint trees. A value
of 32 is RECOMMENDED. Enforcement points MUST reject any constraint tree
whose nesting depth exceeds MAX_CONSTRAINT_DEPTH.

## Extension Constraint Registry

Implementations MAY define extension constraint types beyond those
listed in Section 3.4. Extension constraint types MUST be registered in
the IANA AAT Constraint Type Registry defined in Section 9.3. The
registry exists to preserve security and interoperability in the
presence of domain-specific constraints; it is not a requirement that
all implementations support arbitrary extensions. An enforcement point
that does not recognize a registered extension type MUST deny
authorization (Section 3.5.2), but it is not required to implement that
type.

### Attenuation Compliance Requirement

The capability monotonicity invariant (I4, Section 4.5) applies to
extension constraint types without exception. An extension constraint
type MUST NOT be registered unless its registration defines all of the
following.

**A subsumption verification procedure.** The registration MUST provide
a complete, formal definition of what it means for one instance of the
constraint to be at least as restrictive as another instance of the same
constraint type. This procedure MUST satisfy three properties:

1. **Decidable.** The procedure MUST terminate in finite time for
   all inputs. It MUST NOT require solving problems that are
   undecidable or computationally intractable in the general
   case. If the constraint language used by the type is not
   closed under decidable containment analysis, the registration
   MUST prescribe a conservative syntactic strategy and MUST
   formally justify that the strategy is sound (never accepts
   a non-subsuming pair).

2. **Sound.** The procedure MUST NOT return true unless the
   semantic subsumption relation holds. That is, if the procedure
   returns true for (C_parent, C_child), then for all argument
   values v: C_child.check(v) implies C_parent.check(v). The
   procedure MAY be conservative: it MAY return false for
   semantically subsuming pairs that it cannot verify, but it
   MUST NOT return true for non-subsuming pairs.

3. **Deterministic.** Two independent implementations of the
   procedure MUST produce identical results for the same inputs.
   The procedure MUST be specified precisely enough to ensure
   this. Ambiguity in the specification of the procedure is
   grounds for rejection of the registration.

This specification does not prescribe the internal mechanism of the
subsumption verification procedure. Registrations MAY use structural
comparison of token claims, formal type-checking, proof-carrying tokens,
or any other mechanism that satisfies the three properties above. See
Appendix C for non-normative guidance on policy languages with decidable
containment algorithms.

**Cross-type subsumption rules.** For each core constraint type
defined in Section 3.4, the registration MUST specify whether a
derived token may substitute an extension type instance for a
parent constraint of that core type (or vice versa). If
substitution is permitted, the registration MUST state the
conditions. Any (parent type, child type) pair not explicitly declared
valid MUST be treated as invalid by enforcement points.

### Enforcement Point Obligations

When an enforcement point encounters an extension constraint type during
chain verification, it MUST:

1. Locate the registered subsumption verification procedure for
   that type. If no registration exists, the enforcement point MUST
   reject the chain (fail-closed).

2. Evaluate the subsumption relation at every chain link where
   the constraint appears, as part of the I4 check. A chain link
   where the derived constraint does not subsume the parent
   constraint MUST be rejected.

3. Evaluate the constraint's `check` predicate against the
   presented argument value during authorization. If the predicate
   returns false, the invocation MUST be denied.

An enforcement point that does not implement a registered extension
constraint type MUST deny authorization rather than skip the constraint.
The presence of an unrecognized constraint type in a token represents a
restriction the issuer intended to enforce. Silently omitting that check
would violate the attenuation guarantee.

### Example Registration: Path Containment

The following is an illustrative example of a conforming extension
constraint registration. It is not defined normatively in this document.

**Type name:** `path_containment`

**Additional members:** `root` (string, required). An absolute path
prefix.

**`check` predicate:** The argument, after resolving all `.` and `..`
components and removing redundant separators, must begin with `root`.
The normalization step is part of the predicate; implementations that
compare raw argument strings without normalization do not conform to
this registration.

**`subsumes` relation:** `subsumes(C_parent, C_child)` is true if and
only if `C_child.root` is `C_parent.root` or a descendant of
`C_parent.root` under the normalized path ordering.

**Cross-type subsumption:** A derived `exact` constraint subsumes a
parent `path_containment` constraint if and only if the exact value,
after normalization, begins with the parent's `root`. All other
cross-type pairs involving `path_containment` are invalid.

The following additional examples illustrate conforming extension
registrations for network-oriented constraint types. Neither is defined
normatively in this document.

**Type name:** `cidr`

**Additional members:** `network` (string, required). An IPv4 or IPv6
network in CIDR notation.

**`check` predicate:** The argument must be a valid IPv4 or IPv6 address
string that falls within `network` after normalization of IPv6-mapped
IPv4 addresses, octal notation, and URL-encoded hostnames.
Implementations must normalize address representations before comparison
to prevent encoding bypasses.

**`subsumes` relation:** `subsumes(C_parent, C_child)` is true if and
only if `C_child.network` is a subnet of `C_parent.network`.

**Cross-type subsumption:** A derived `exact` constraint subsumes a
parent `cidr` constraint if and only if the exact value, after
normalization, is an address within the parent's network. All other
cross-type pairs involving `cidr` are invalid.

**Type name:** `url_safe`

**Additional members:** `allow_schemes` (array of strings, optional,
default `["http", "https"]`); `allow_domains` (array of strings,
optional); `deny_domains` (array of strings, optional); `block_private`
(boolean, optional, default true); `block_loopback` (boolean, optional,
default true); `block_metadata` (boolean, optional, default true).

**`check` predicate:** The argument must be a URL whose scheme appears
in `allow_schemes`. If `block_private`, `block_loopback`, or
`block_metadata` are true, the resolved host must not be a private,
loopback, or cloud metadata address respectively, after normalization of
all known IP encoding forms (decimal, hex, octal, IPv6-mapped,
URL-encoded). If `allow_domains` is non-empty, the host must match at
least one entry. If `deny_domains` is non-empty, the host must not match
any entry. `deny_domains` takes precedence over `allow_domains` on
overlap.

**`subsumes` relation:** `subsumes(C_parent, C_child)` is true if and
only if `C_child` is at least as restrictive as `C_parent` on every
field: `allow_schemes` is a subset of parent's; `block_private`,
`block_loopback`, and `block_metadata` are each equal to or more
restrictive than the parent's corresponding flag; `allow_domains` is a
subset of parent's (or parent has none); `deny_domains` is a superset of
parent's.

**Cross-type subsumption:** A derived `exact` constraint subsumes a
parent `url_safe` constraint if and only if the exact value passes the
parent's `check` predicate. All other cross-type pairs involving
`url_safe` are invalid.

## Examples

### Root Token

~~~json
{
  "jti": "01957a3f-4e23-7b01-a9d1-0050569c2e4f",
  "iss": "https://auth.example.com",
  "iat": 1741600000,
  "exp": 1741603600,
  "del_depth": 0,
  "del_max_depth": 3,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  },
  "authorization_details": [
    {
      "type": "attenuating_agent_token",
      "tools": {
        "read_file": {
          "path": {
            "constraint_type": "one_of",
            "values": ["/data/q3-report.pdf", "/data/q4-report.pdf"]
          }
        },
        "search_index": {}
      }
    }
  ]
}
~~~

### Derived Token

~~~json
{
  "jti": "01957a41-0081-7c20-bf3a-00a0c91e1234",
  "iss": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:KAKnRDlMQVIKCfS5JhHlABCHjAFLdyEVVHdpnGnLLg8",
  "iat": 1741600120,
  "exp": 1741601920,
  "del_depth": 1,
  "del_max_depth": 3,
  "par_hash": "sha256_base64url_of_parent_token_signing_input",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "rAl9xvTDAeUADPnIWlGpFHtGg4Y8OqcQE5N4XYNdLPs"
    }
  },
  "authorization_details": [
    {
      "type": "attenuating_agent_token",
      "tools": {
        "read_file": {
          "path": {
            "constraint_type": "exact",
            "value": "/data/q3-report.pdf"
          }
        }
      }
    }
  ]
}
~~~

Note that the derived token:

- Carries a `par_hash` linking it to its parent.
- Has `del_depth` incremented to 1.
- Restricts `read_file` to a single file rather than either file
  authorized by the parent.
- Omits `search_index`, which the parent permitted. Tool omission
  is valid attenuation.
- Expires 1800s after its own issuance, versus the parent's 3600s
  window.

## Root Issuer Support and Root Token Issuance

### Root Issuer Discovery

A root issuer that supports AAT issuance SHOULD advertise this
capability using the following metadata parameter in its
authorization server metadata document {{RFC8414}}, if supported.

| Metadata Parameter | Value |
|---|---|
| `aat_issuer` | Boolean. `true` if the AS can issue AAT root tokens. |

This document requests registration of `aat_issuer` in the IANA OAuth
Authorization Server Metadata registry (Section 9.4).

### Agent Token Request

An agent requesting a root AAT MUST include a `req_cnf` parameter in its
token endpoint request (in the OAuth 2.0 sense, the agent acts as the
client for this request). This specification profiles the `req_cnf`
token request parameter defined by {{RFC9201}} for AAT root token
issuance. The parameter carries a key confirmation object whose JSON
syntax and semantics follow {{RFC7800}} Section 3.1. This document does
not define a new OAuth token endpoint key-confirmation parameter. The
value MUST be a JSON object containing a `jwk` member with the agent's
public key in JWK format {{RFC7517}}. This is the key that the root
issuer will bind into the root token's `cnf.jwk` claim.

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&authorization_details=%5B%7B%22type%22%3A%22attenuating_agent_
  token%22%2C...%7D%5D
&req_cnf=%7B%22jwk%22%3A%7B%22kty%22%3A%22OKP%22%2C...%7D%7D
~~~

The request MUST also include `authorization_details` in RAR format
{{RFC9396}} with `type` set to `attenuating_agent_token`, enumerating
the tools and argument constraints the agent is requesting authority to
invoke or delegate.

### Root Token Issuance

Upon a valid request, the AS constructs and returns a root AAT. The AS:

1. Sets `iss` to the AS's own URI.
2. Sets `jti` to a unique token identifier, RECOMMENDED to be
   a UUIDv7 value per {{RFC9562}}.
3. Sets `iat` to the current time and `exp` to the token's
   expiry time, subject to the constraints in Section 4.4.
4. Sets `del_depth` to 0, `del_max_depth` to the maximum
   delegation depth permitted for this grant, and `par_hash`
   to absent.
5. Sets `cnf.jwk` to the public key submitted in the agent's
   `req_cnf` request parameter. The root issuer MUST validate that
   the submitted key is well-formed and is a public key. The
   root issuer SHOULD require the agent to demonstrate
   possession of the corresponding private key, for example via
   a signed proof-of-possession assertion in the token request.
6. Sets `authorization_details` to the capability claims
   granted, which MAY be a subset of what the agent requested.
7. For each URI-format tool identifier in the requested
   `authorization_details`, the root issuer SHOULD verify that
   the requesting agent's identity, as established by the
   agent's client authentication credentials, corresponds to
   the authority component of each claimed tool URI. If this
   verification fails, the root issuer MUST reject the request.
   The mechanism by which agent identity is mapped to tool URI
   authority is deployment-specific and outside the scope of
   this specification.
8. Signs the token with the AS's own private key.

The AS returns the token in a standard OAuth 2.0 token endpoint response
({{RFC6749}} Section 5.1) with the following field values:

~~~
{
  "access_token": "<compact-serialized AAT JWT>",
  "token_type": "aat",
  "expires_in": <seconds until exp>
}
~~~

The `token_type` value `"aat"` is registered in Section 9.5. Clients
MUST NOT treat the returned token as a bearer token for use with
arbitrary resource servers. Its only valid use is as the root of an AAT
delegation chain presented to an enforcement point per Section 7.

Note: this specification defines token endpoint issuance for
interoperability with existing OAuth 2.0 deployments. Unlike bearer
tokens, an AAT carries its own holder key binding and is not usable as a
credential for HTTP resource access. Alternative issuance profiles are
outside the scope of this document.

The AS does not need to store or track derived tokens issued downstream
by the initial token holder. Chain verification is performed by
enforcement points using only the root token's public key as a trust
anchor.


# Attenuation Invariants

Every derived token in a chain MUST satisfy all of the following
invariants. The verification algorithm in Section 7 enforces these
invariants; enforcement points MUST reject any chain that violates
any invariant.

## Capability Lattice Model (Non-Normative)

The attenuation invariants in this section are instances of a single
abstract structure: a capability lattice. This subsection states that
structure informally to give readers a mental model for interpreting the
normative rules that follow.

For a token `T`, define its capability set `C(T)` as the set of `(tool,
args)` pairs that `T` authorizes (that is, the pairs for which `T` would
permit invocation). The core security property of this protocol is:

~~~
C(child) ⊆ C(parent)
~~~

Every delegation step moves down or stays at the same position in this
partial order. A derived token can only authorize a subset of what its
parent authorized. It cannot add tools, loosen argument constraints, or
extend the chain's authority in any dimension.

The `⊆` relation is not defined by enumerating `(tool, args)` pairs
(argument spaces are typically infinite) but by the structural
subsumption rules in Section 4.5. At the tool level, the derived
token's tool set must be a subset of the parent's. At the argument
level, when the parent's constraint map is non-empty, the derived
token must preserve the parent's key set exactly (Section 4.5
explains why closed-world semantics require this).

When the parent's map is empty, the derived token may introduce
keys, transitioning from open-world to closed-world. Each per-key
constraint must be at least as restrictive. A derived constraint
`c_child` subsumes a parent constraint `c_parent` (written
`c_child ⊑ c_parent`) if every argument value that satisfies
`c_child` also satisfies `c_parent`.

Two boundary cases complete the structure. The empty capability set
`∅` is the bottom element: a token with no tools authorized is a
valid but useless terminal token. The root token's capability set is the ceiling
for the entire chain: no derived token at any depth can exceed what the
root authorized.

Token lifetime (I3) is a mandatory attenuation dimension orthogonal to
the capability lattice. A derived token with `C(child) == C(parent)` is
still strictly more constrained if its `exp` is earlier than its
parent's. Time-to-live (TTL) bounds are enforced independently of
capability monotonicity. Both must hold for a chain to be valid.

Invariants I1 through I6 are the normative enforcement mechanism for
this property. I4 (Section 4.5) directly enforces `C(child) ⊆
C(parent)`. The remaining invariants enforce the conditions under which
that comparison is meaningful: that the chain is cryptographically
linked (I1, I5), that depth and time bounds are respected (I2, I3), and
that the presenter holds the key (I6).

## I1: Delegation Authority

~~~
derived.iss == jwk_thumbprint_uri(parent.cnf.jwk)
~~~

where `jwk_thumbprint_uri` constructs the {{RFC9278}} URI from the
key's SHA-256 thumbprint. The entity that signed the derived token
MUST be the holder of the parent token. Authority flows from parent
holder to derived token issuer. This invariant establishes an
unambiguous audit trail: each link
in the chain was signed by the party that held the preceding token.

## I2: Depth Monotonicity

~~~
derived.del_depth == parent.del_depth + 1
derived.del_depth <= parent.del_max_depth
derived.del_depth <= derived.del_max_depth
derived.del_depth <= MAX_DELEGATION_DEPTH
derived.del_max_depth <= parent.del_max_depth
~~~

Delegation depth increments exactly by one at each link. The chain
cannot skip depths, branch, or exceed the maximum depth established in
the root token. `del_max_depth` is an absolute ceiling, not a remaining
count. A token is terminal (its holder cannot derive further tokens)
when `del_depth == del_max_depth`. A root token with `del_max_depth: 0`
is therefore immediately terminal and cannot produce any derived tokens.

The `del_max_depth` claim serves two related purposes. First, it is a
security boundary: each delegation hop is a trust extension, delegating
authority through another agent whose key, runtime, and behavior must be
trusted to maintain the attenuation invariant. Unbounded chains mean
unbounded trust extensions; the depth limit constrains how far authority
can propagate before it must be reissued from the root. Second, it is a
policy expression by the root issuer: a root token with
`del_max_depth: 2` asserts that this grant of authority should pass
through no more than two intermediate agents, regardless of what those
agents might prefer. Intermediate token holders can only lower
`del_max_depth`, never raise it (I2), so the root issuer's topology
constraint is cryptographically enforced across the entire chain.

MAX_DELEGATION_DEPTH is an implementation-defined finite integer
specifying the maximum permitted delegation chain depth. Implementations
MUST enforce a finite maximum delegation depth to prevent resource
exhaustion from pathologically deep chains. The appropriate value
depends on the deployment topology; swarm architectures with deep
fan-out may require significantly larger values than linear delegation
chains. See Appendix B.5 for guidance.

The `del_max_depth` claim in any token in the chain MUST NOT exceed the
implementation's MAX_DELEGATION_DEPTH.

### Implementation Resource Limits

MAX_TOKEN_SIZE is an implementation-defined finite integer specifying
the maximum encoded size of a single token in bytes. Implementations
MUST enforce this limit to prevent memory exhaustion from pathologically
large tokens. A value of 65536 bytes (64 KiB) is RECOMMENDED.

MAX_STACK_SIZE is an implementation-defined finite integer specifying
the maximum total encoded size of a chain in bytes. Implementations MUST
enforce this limit. A value of 262144 bytes (256 KiB) is RECOMMENDED.

## I3: TTL Monotonicity

~~~
derived.exp  <= parent.exp
derived.exp  >  now
derived.exp  >  derived.iat
derived.iat  >= parent.iat
derived.iat  <= now + MAX_IAT_SKEW
derived.exp  <= derived.iat + MAX_TOKEN_LIFETIME
~~~

MAX_IAT_SKEW is an implementation-defined finite integer specifying the
maximum number of seconds a token's `iat` may be in the future relative
to the enforcement point's clock. Implementations MUST enforce a finite
MAX_IAT_SKEW. A value of 30 seconds is RECOMMENDED.

MAX_TOKEN_LIFETIME is an implementation-defined finite integer
specifying the maximum permitted duration in seconds between a token's
`iat` and `exp`. Implementations MUST enforce a finite
MAX_TOKEN_LIFETIME. A value of 90 days is RECOMMENDED as an upper bound;
deployments SHOULD use significantly shorter lifetimes in practice (see
Appendix B.8).

A derived token cannot outlive its parent. Authority cannot extend
beyond the lifetime of the token that granted it. A derived token's
issuance time MUST NOT precede its parent's issuance time. A token with
an earlier `iat` indicates clock manipulation or chain forgery. Tokens
with `iat` more than MAX_IAT_SKEW in the future relative to the
enforcement point's clock MUST be rejected. A token's lifetime
MUST NOT exceed MAX_TOKEN_LIFETIME.

## I4: Capability Monotonicity

~~~
tools(derived) ⊆ tools(parent)
∀ tool ∈ tools(derived):
  constraints(derived, tool) ⊑ constraints(parent, tool)
~~~

A derived token MUST NOT authorize tools that the parent did not
authorize. For each tool that appears in both parent and derived token:

- If the parent's constraint map for that tool is non-empty, the
  derived token's constraint map MUST contain exactly the same set
  of argument keys. Under closed-world semantics (Section 3.3),
  the constraint map keys define the required invocation shape:
  any argument not named is forbidden, and any named argument must
  be present. Adding a key would produce invocations that the
  parent's closed-world check rejects (the extra argument is
  unknown). Dropping a key would produce invocations that omit a
  parent-required argument. In both cases the derived invocation
  set is disjoint from the parent's, not a subset.

- If the parent's constraint map is empty (open-world), the derived
  token MAY introduce constraint keys, transitioning to
  closed-world. Any closed-world constraint set is a subset of the
  unrestricted open-world set.

For each argument constraint key present in both parent and derived
token, the derived constraint MUST be at least as restrictive as the
parent's constraint.

Constraint subsumption is defined per constraint type. The normative
rules are:

- **exact:** A derived `exact` constraint subsumes a parent
  constraint of the same or different type as follows: it subsumes
  a parent `exact` if the values are identical; it subsumes a parent
  `range` if the exact value is a number that falls within the parent
  range; it subsumes a parent `one_of` if the exact value is a member of
  the parent set; it subsumes a parent `wildcard` unconditionally. All
  other parent types are invalid cross-type targets for a derived `exact`
  constraint.

- **range:** A derived `range` constraint is valid only if its
  bounds are at least as restrictive as the parent's
  (derived `min >= parent min`, derived `max <= parent max`).
  A missing bound on the parent is treated as unbounded; a
  missing bound on the derived constraint is only valid if the parent
  bound is also missing. A derived bound's inclusivity may only become
  more restrictive: a derived `min_inclusive: false` is valid when the
  parent has `min_inclusive: true` at the same `min` value (exclusive is
  strictly tighter), but the reverse is not. The same applies to
  `max_inclusive`.

- **one_of:** A derived `one_of` constraint is valid only if
  its value set is a subset of the parent's value set.
  Cross-type pairs involving a derived `not_one_of` against a
  parent `one_of` are invalid: a `not_one_of` constraint
  accepts values outside the parent's permitted set and
  cannot be verified as subsuming a `one_of` without domain knowledge.
  Enforcement points MUST reject this cross-type pair.

- **not_one_of:** A derived `not_one_of` constraint is valid
  only if its excluded set is a superset of the parent's excluded
  set (can only add exclusions, never remove them).

- **wildcard:** A derived `wildcard` is valid only if the parent
  is also `wildcard`. Any other constraint type subsumes a
  parent `wildcard`.

- **all:** A derived `all` constraint is valid attenuation of a
  parent `all` if the derived constraint contains all clauses
  present in the parent (none may be dropped) and each
  corresponding clause satisfies the subsumption relation.
  The derived constraint MAY add additional clauses at any
  position, which only further restrict the accepted
  value set. Dropping any parent clause from the derived `all` would
  expand authority and MUST be rejected.

  Clause matching for `all` is subsumption-based: for each clause C_p in
  the parent array, the enforcement point MUST find at least one clause
  C_d in the derived array such that C_d subsumes C_p per this section.
  Each parent clause MUST be matched to a
  distinct derived clause (one-to-one assignment); a single derived
  clause MUST NOT be used to satisfy more than one parent clause. If any
  parent clause cannot be matched, the check MUST fail. Unmatched
  additional clauses in the derived array are permitted.

  The following pseudocode describes the matching algorithm.
  Because the one-to-one assignment requirement is order-sensitive, the
  algorithm backtracks when a greedy match leads to a dead end.

  ~~~
  function check_all_subsumption(parent_clauses, derived_clauses):
    used = set()
    return match(parent_clauses, 0, derived_clauses, used)

  function match(parents, idx, derived, used):
    if idx == len(parents):
      return PASS
    C_p = parents[idx]
    for i, C_d in enumerate(derived):
      if i not in used and subsumes(C_d, C_p):
        used.add(i)
        if match(parents, idx + 1, derived, used) == PASS:
          return PASS
        used.remove(i)    // backtrack
    return FAIL
  ~~~

  The search space is bounded by the number of parent and derived
  clauses. Implementations MAY employ Hopcroft-Karp or similar maximum
  matching algorithms for the general case.

- **any:** A derived `any` constraint subsumes a parent `any`
  constraint if every clause in the derived constraint is
  subsumed by at least one clause in the parent constraint,
  using the per-type subsumption rules defined in this section.
  Formally: for each `clause_d` in
  `derived.any.constraints`, there MUST exist a `clause_p` in
  `parent.any.constraints` such that `clause_d ⊑ clause_p`.
  Removing clauses is valid (it narrows the accepted set).
  Adding clauses is invalid (it widens it). The derived `any`
  MUST contain at least one clause. Cross-type subsumption
  between clauses is permitted: for example, a derived clause
  of `exact("pdf")` is subsumed by a parent clause of
  `one_of(["pdf", "csv"])` under the cross-type rules in this section.

  Example: a parent token carries
  `any([exact("pdf"), exact("csv"), exact("xlsx")])`. A derived
  token MAY carry `any([exact("pdf"), exact("csv")])` because
  each derived clause is subsumed by a parent clause. A derived
  token MUST NOT carry `any([exact("pdf"), exact("docx")])`
  because `exact("docx")` is not subsumed by any parent
  clause.

- **contains:** A derived `contains` constraint is valid
  attenuation of a parent `contains` if the derived `required` set
  is a superset of the parent's `required` set. Requiring
  additional elements is a restriction; removing required
  elements would expand the set of accepted argument
  arrays and MUST be rejected.

- **subset:** A derived `subset` constraint is valid attenuation
  of a parent `subset` if the derived `allowed` set is a subset
  of the parent's `allowed` set. Shrinking the allowed set is
  a restriction; adding allowed elements would expand the set
  of accepted argument arrays and MUST be rejected.

Any (parent constraint type, derived constraint type) pair not
explicitly permitted by the above rules, or by a registered extension
constraint's cross-type subsumption declaration (Section 3.5.1), MUST be
rejected.

## I5: Cryptographic Linkage

~~~
derived.par_hash ==
  base64url-nopad(SHA-256(parent token signing input))
~~~

Token signatures and `par_hash` serve distinct security roles. Signature
verification authenticates each token under the verification key selected
for that token: a trust anchor for a root token, or the parent token's
`cnf.jwk` for a derived token. Delegation authority (I1) then checks
that the child issuer corresponds to the parent holder key. However,
these checks do not by themselves bind the child to a unique parent
token instance when the same holder key has multiple compatible parent
tokens. The `par_hash` claim provides that token-instance binding by
committing the child to exactly one parent token's signing input.

Each derived token is cryptographically bound to its parent by including
the SHA-256 digest of the parent token's signing input in the
`par_hash` claim. For JWT/JWS AATs, the parent token signing input is
the JWS Signing Input: the ASCII string
`BASE64URL(JWS Protected Header) || '.' || BASE64URL(JWS Payload)` as
defined in {{RFC7515}} Section 5.1.

This binding prevents grant-context substitution: a child token signed
by a key that holds multiple compatible parent tokens cannot be
re-associated with a different parent task grant. The capability set may
still be attenuated, but the task/session lineage, revocation ancestry,
approval context, or policy snapshot would change.

## I6: Proof of Possession

~~~
pop_signature verifies under derived.cnf.jwk
~~~

The presenter of a token chain MUST demonstrate control of the private
key corresponding to the leaf token's `cnf.jwk`. Proof of Possession is
defined in Section 5.


# Proof of Possession

## Rationale

A token without proof of possession can be replayed by any party that
obtains a copy of the token. In agent systems, tokens flow through
model context, tool invocation results, and inter-agent message
channels, all of which are observable by other components. PoP
binds a specific invocation to the private key of the leaf
token's holder.

## PoP Token Structure

The holder of the leaf token produces a PoP JWT for each tool
invocation. The PoP JWT is a compact serialization signed with the
holder's private key. It MUST contain the required claims listed below.

| Claim | Type | Required | Description |
|---|---|---|---|
| `jti` | string | REQUIRED | Fresh random identifier. Issuers MUST NOT generate the same `jti` value for two different PoP JWTs. When a UUID is used, it MUST be encoded as a lowercase hyphenated string per {{RFC9562}}. Whether an enforcement point can detect reuse depends on whether stateful `jti` tracking is deployed (see Section 8.6). |
| `iat` | NumericDate | REQUIRED | Time of PoP creation. MUST reflect the actual time of creation. Enforcement points validate this against a clock tolerance window (see Section 5.3). |
| `aat_id` | string | REQUIRED | The `jti` of the leaf token being presented. |
| `aat_tool` | string | REQUIRED | The tool identifier being invoked. MUST exactly match a key in the `tools` map of the leaf token's `authorization_details`. Tool identifiers are compared as byte strings; no Unicode normalization is applied. |
| `aat_aud` | string | OPTIONAL | Audience identifier for the enforcement point or resource accepting the PoP JWT. Deployments or profiles that require audience binding MUST require this claim and enforce audience match at verification time. |
| `hta` | object | REQUIRED | The tool arguments for this invocation. Keys are argument names; values are argument values. |

The PoP JWT payload MUST be serialized as JCS-canonical JSON
({{RFC8785}}) before JWS signing. This is a whole-payload requirement,
not specific to the `hta` member. The JWS signing input is therefore
`BASE64URL(JWS Protected Header) || '.' || BASE64URL(JCS(PoP claims))`.
Whole-payload JCS canonicalization ensures a deterministic byte
representation; in particular, it gives `hta` stable equality semantics
so that argument map comparison is unambiguous across implementations
and languages regardless of JSON serialization choices.

The PoP JWT MUST be signed using the private key corresponding to the
leaf token's `cnf.jwk`. The enforcement point verifies the PoP JWT
signature against the leaf token's `cnf.jwk`.

~~~json
{
  "jti": "c980f2a1-4a37-4e88-bb3c-9defd37c1a45",
  "iat": 1741600300,
  "aat_id": "01957a41-0081-7c20-bf3a-00a0c91e1234",
  "aat_tool": "read_file",
  "aat_aud": "https://tools.example.com",
  "hta": { "path": "/data/q3-report.pdf" }
}
~~~

## Verification

PoP verification is only meaningful against a leaf token whose chain has
been fully verified per Section 7. An enforcement point MUST complete
chain verification (Section 7, steps 1-6) before evaluating the PoP JWT.
A valid PoP JWT against an unverified or invalid chain MUST NOT result
in authorization.

The enforcement point MUST reject a PoP JWT that:

1. Has a signature that does not verify under the leaf token's
   `cnf.jwk`.
2. References an `aat_id` that does not match the `jti` of the
   presented leaf token.
3. When deployment policy requires PoP audience binding, omits
   `aat_aud` or contains an `aat_aud` claim that does not identify
   the enforcement point or resource accepting the invocation.
4. Names a tool in `aat_tool` that is not authorized by the leaf
   token.
5. Presents arguments in `hta` that violate constraints in the
   leaf token, per the verification algorithm in Section 7
   (step 6b).
6. Has `iat` that is outside the enforcement point's accepted
   clock tolerance window (RECOMMENDED: ±30 seconds).

The PoP JWT `iat` timestamp and clock tolerance window bound the replay
surface to a short interval. Implementations that wish to avoid shared
state MAY use fixed-width time buckets (for example, accepting PoP JWTs
whose `iat` falls within the current or immediately preceding 30-second
bucket) to simplify enforcement point implementation.

Note: The time bucket approach is stateless but probabilistic: a PoP JWT
captured early in a bucket remains usable until the end of the following
bucket. This approach MUST NOT be used for tool invocations that have
side effects or are not idempotent. For any tool invocation where
duplicate execution causes unintended side effects, stateful
`jti` tracking MUST be used.

Full replay prevention — guaranteeing that a given PoP JWT is accepted
at most once — requires stateful tracking of presented `jti` values
across all enforcement points in a deployment. The mechanism for that
state (shared cache, database, token-binding infrastructure) is
deployment-specific and outside the scope of this specification.
Deployments with strong replay prevention requirements SHOULD consult
the security considerations in Section 8.6.


# Token Derivation

A holder of any AAT whose `del_depth` is strictly less than
`del_max_depth` MAY derive a child token as follows.

1. Set `jti` to a fresh unique token identifier, RECOMMENDED to
   be a UUIDv7 value per {{RFC9562}}.

2. Set `iat` to the current time. Set `exp` to any value <=
   `parent.exp`, subject to the constraints in Section 4.4.
   Token lifetime is a mandatory attenuation dimension. Every
   derived token is temporally bounded by its parent regardless
   of capability scope. TTL is the primary revocation mechanism
   in this specification; see Appendix B.8 for deployment guidance.

3. Select the set of tools to authorize. This set MUST be a
   subset of the tools authorized by the parent token.

4. For each tool, construct a constraint map with the same
   argument keys as the parent's constraint map for that tool
   (Section 4.5). For each key, select a constraint that is at
   least as restrictive as the parent's, per the subsumption
   rules in Section 4.5. If the parent's constraint map is
   empty, the derived token MAY introduce constraint keys.

5. Set `del_depth` to `parent.del_depth + 1`.

6. Set `del_max_depth` to any integer value greater than or equal
   to `child.del_depth` and less than or equal to
   `parent.del_max_depth`. Setting `del_max_depth` equal to
   `child.del_depth` produces a terminal token that cannot be
   further delegated; higher values permit further delegation up
   to the parent's ceiling. Both bounds are inclusive; the upper
   bound enforces I2.

7. Set `par_hash` to `base64url(SHA-256(parent token signing
   input))`, using base64url encoding without padding
   ({{RFC7515}} Appendix C). For JWT/JWS AATs, the parent
   token signing input is the JWS Signing Input.

8. Set `cnf.jwk` to the intended holder's public key. The
   value MUST be a public key; private key material MUST NOT
   appear in this field.

9. Sign the token with the private key corresponding to the
    parent token's `cnf.jwk`. The `iss` claim MUST be set to the
    JWK Thumbprint URI {{RFC9278}} of that signing key, using the
    SHA-256 hash algorithm.

Derivation is performed locally by the token holder. No authorization
server communication is required.

A derivation in which none of the above dimensions is strictly
narrowed (the tool set is identical, all constraints are unchanged,
`del_max_depth` is unchanged, and `exp` is unchanged) is technically
valid by the invariants. However, it produces a child token with
authority identical to its parent, while consuming one delegation
depth. Such derivations serve no purpose from a least-privilege
standpoint and SHOULD NOT be issued. Enforcement points
MAY log same-scope derivations as anomalous.


# Chain Verification Algorithm

The enforcement point receives a chain of tokens ordered from root to
leaf and MUST execute the following algorithm. Any failure MUST result
in denial.

Verification requires only the token chain and the trust anchor public
key. No network calls or authorization server availability are required.
Chain verification itself is fully offline. Strong replay protection for
side-effecting tool invocations may additionally require stateful `jti`
tracking as described in Section 8.6; that state is outside the inputs
of this algorithm.

~~~
Inputs:
  chain:         ordered array of signed JWTs, [root, ..., leaf]
  trust_anchors: set of public keys trusted as root issuers
  tool:          the tool being invoked
  args:          the arguments being passed to the tool
  pop_jwt:       the PoP JWT presented by the agent

Algorithm:

1. If chain is empty, DENY.

2. Verify chain size limits:
   a. Verify the encoded size of each token does not exceed
      MAX_TOKEN_SIZE. If any token exceeds this limit, DENY.
   b. Verify the total encoded size of the chain does not exceed
      MAX_STACK_SIZE. If the chain exceeds this limit, DENY.
   c. For each token, decode the base64url payload segment and
      extract only the `jti` field using minimal JSON parsing.
      If the payload is not valid JSON or does not contain a
      string-valued `jti` field, DENY. Collect all extracted
      `jti` values; if any value appears more than once in the
      chain, DENY (cycle detection). This limited extraction
      prior to signature verification is permitted and required
      for this structural check; it does not constitute the
      application-layer claim deserialization prohibited by the
      post-algorithm note. The extracted `jti` values MUST be
      treated as untrusted until each token's signature is
      verified. Full claim parsing MUST still be deferred until
      after signature verification succeeds for each token.

3. Verify root token:
   a. Verify the root token's JWS alg header is on the
      implementation's permitted algorithm allowlist and is
      consistent with the verifying trust anchor key's kty and
      crv parameters. If alg is "none", not on the allowlist,
      or inconsistent with the key type, DENY.       [Sec 8.13]
   b. Verify the root token signature against a key in
      trust_anchors. After signature verification succeeds,
      parse the root token's claims. All subsequent root
      checks (3c through 3n) operate on parsed claims.
   c. Verify root.del_depth == 0.
   d. Verify root.par_hash is absent.
   e. Verify root.exp > now.
   f. Verify root.iat <= now + MAX_IAT_SKEW.
   g. Verify root.exp > root.iat.
   h. Verify root.exp <= root.iat + MAX_TOKEN_LIFETIME.
   i. Verify root.del_max_depth is a non-negative integer not
      exceeding MAX_DELEGATION_DEPTH. If absent or invalid, DENY.
   j. Verify root.jti is present and is a non-empty string.
      If absent or not a string, DENY.
   k. Verify root.iss is present and is a URI. If absent or
      not a URI-formatted string, DENY.
   l. Verify root.cnf is present, contains a `jwk` member, and
      that the `jwk` encodes a public key (MUST NOT contain a
      private key parameter such as `d` for EC/OKP keys or
      `p`, `q` for RSA keys). If absent or invalid, DENY.
   m. Verify root.authorization_details is present and is a
      non-empty array containing exactly one entry with type
      "attenuating_agent_token". If absent, empty, or if the
      number of such entries is not exactly one, DENY.
      Note: for a single-token chain (root = leaf), step 4 has
      no adjacent parent-child pair to evaluate. Validation is
      therefore performed by step 3 (root checks), step 5
      (chain-length consistency), step 6 (leaf
      capability/constraint checks), and step 7 (PoP), before
      permit in step 8.
      Steps 3j through 3m ensure that required claims are
      present before step 6 depends on them, closing the
      bypass window that exists when step 4 does not run.
   n. For each constraint in each constraint map in the root
      token's attenuating_agent_token entry, verify the
      constraint tree depth does not exceed MAX_CONSTRAINT_DEPTH.
      If any constraint tree exceeds this limit, DENY.

4. For each adjacent pair (parent, child) in chain:
   a. Verify child token's JWS alg header is on the
      implementation's permitted algorithm allowlist and is
      consistent with parent.cnf.jwk's kty and crv parameters.
      If alg is "none", not on the allowlist, or inconsistent
      with the key type, DENY.                       [Sec 8.13]
   b. Verify child signature under the key in parent.cnf.jwk. [I1]
      After signature verification, verify required claims are
      present:
      b1. Verify child.jti is present and is a non-empty
          string. If absent or not a string, DENY.
      b2. Verify child.cnf is present, contains a `jwk`
          member, and that the `jwk` encodes a public key
          (MUST NOT contain a private key parameter such as
          `d` for EC/OKP keys or `p`, `q` for RSA keys). If
          absent or invalid, DENY.
      b3. Verify child.authorization_details is present and
          is an array. If absent or not an array, DENY.
      b4. Verify child.del_depth and child.del_max_depth are
          both present and are non-negative integers. If
          absent or not integers, DENY.
      b5. Verify child.iss, child.iat, child.exp, and
          child.par_hash are all present. If any is absent, DENY.
   c. Verify child.iss equals jwk_thumbprint_uri(parent.cnf.jwk). [I1]
   d. Verify child.del_depth == parent.del_depth + 1.    [I2]
   e. Verify child.del_depth <= parent.del_max_depth.    [I2]
   f. Verify child.del_depth <= MAX_DELEGATION_DEPTH.    [I2]
   g. Verify child.del_max_depth <= parent.del_max_depth.[I2]
      Note: the requirement that every token's
      del_max_depth <= MAX_DELEGATION_DEPTH is transitively
      satisfied: step 3i verifies this for the root, and
      step 4g at each link ensures the value can only
      decrease. Implementations MAY add this check
      explicitly as defense in depth.
   h. Verify child.exp <= parent.exp.                    [I3]
   i. Verify child.exp > now.                            [I3]
   j. Verify child.iat >= parent.iat.                    [I3]
   k. Verify child.iat <= now + MAX_IAT_SKEW.            [I3]
   l. Verify child.exp > child.iat.                      [I3]
      Note: the requirement child.exp <= child.iat +
      MAX_TOKEN_LIFETIME is transitively satisfied: by
      induction, child.exp <= root.exp (step 4h at each
      link), root.exp <= root.iat + MAX_TOKEN_LIFETIME
      (step 3h), and child.iat >= root.iat (step 4j at
      each link), therefore child.exp <= root.iat +
      MAX_TOKEN_LIFETIME <= child.iat + MAX_TOKEN_LIFETIME.
      Implementations MAY add this check explicitly as
      defense in depth.
   m. Verify child.del_depth <= child.del_max_depth.     [I2]
   n. Verify child.authorization_details contains at most
      one entry with type "attenuating_agent_token". If
      more than one such entry is present, DENY. Note: zero
      entries of this type are permitted at this step and
      represent an empty capability set. Step 4p will verify
      this is a valid attenuation of the parent (an empty tool
      set is always a subset). If the child is the leaf token,
      step 6a will reject zero entries.
      For the remaining checks in this adjacent-pair step, define
      child_aat as the child entry with type
      "attenuating_agent_token" if present, or as an empty capability
      entry with an empty `tools` map if absent. Define parent_aat
      the same way for the parent token: the parent entry with type
      "attenuating_agent_token" if present, or an empty capability
      entry with an empty `tools` map if absent. Root validation
      (step 3m) ensures the root parent has such an entry; non-root
      parents with zero entries represent the empty capability set.
      Entries of other types in `authorization_details` are ignored
      by this algorithm.
   o. For each constraint in each constraint map in child_aat.tools,
      verify the constraint tree depth does not exceed
      MAX_CONSTRAINT_DEPTH. If any constraint tree exceeds
      this limit, DENY.
   p. Verify capability monotonicity (Section 4.5):   [I4]
      p1. Verify every tool in child_aat.tools
          is also present in parent_aat.tools.
          If any child tool is absent from the parent, DENY.
      p2. For each tool present in both parent_aat.tools and
          child_aat.tools: if the parent's constraint map is
          non-empty, verify the child's constraint map contains
          exactly the same set of argument keys. If any key is
          added or removed, DENY.
      p3. For each tool present in both parent_aat.tools and
          child_aat.tools: if the parent's constraint map is empty,
          the child's constraint map MAY contain any set of keys.
      p4. For each argument key present in both constraint maps
          for a matched tool, verify the child's constraint subsumes
          the parent's per the per-type rules in Section 4.5. If
          any constraint fails subsumption, DENY.
   q. Verify child.par_hash equals base64url-nopad(      [I5]
      SHA-256(parent token signing input)), where
      base64url-nopad denotes base64url encoding without
      padding per {{RFC7515}} Appendix C. For JWT/JWS AATs,
      the parent token signing input is the JWS Signing Input.

5. (Defense in depth) Verify len(chain) equals
   leaf.del_depth + 1. A mismatch indicates a malformed
   or incorrectly assembled chain.

6. Verify leaf token:
   a. Verify leaf.authorization_details contains exactly one
      entry with type "attenuating_agent_token". If zero or
      more than one such entry is present, DENY.
      Define leaf_aat as that entry. Entries of other types in
      `authorization_details` are ignored by this algorithm.
   b. Verify tool is present in leaf_aat.tools. Then, for each argument
      in args: if the tool's constraint map is non-empty and
      the argument name is not present in the constraint map,
      DENY (closed-world mode). For each argument name present
      in the constraint map, if that argument is absent from
      args, DENY (constrained argument MUST be present). For
      each argument name present in both the constraint map
      and args, verify the argument value satisfies the
      constraint.

7. Verify PoP JWT:
   a. Verify the PoP JWT's JWS alg header is on the
      implementation's permitted algorithm allowlist and is
      consistent with leaf.cnf.jwk's kty and crv parameters.
      If alg is "none", not on the allowlist, or inconsistent
      with the key type, DENY.                       [Sec 8.13]
   b. Verify pop_jwt signature under leaf.cnf.jwk. After
      signature verification succeeds, parse the PoP JWT claims. [I6]
   c. Verify pop_jwt.aat_id == leaf.jti.
   d. If deployment policy requires PoP audience binding, verify
      pop_jwt.aat_aud identifies this enforcement point or resource
      context. If absent or mismatched, DENY.
   e. Verify pop_jwt.aat_tool == tool.
   f. Verify pop_jwt.hta, when JCS-canonicalized
      ({{RFC8785}}), equals the JCS-canonical form of the
      args map for this invocation. If the canonical byte
      sequences differ, DENY.
   g. Verify pop_jwt.iat is within the clock tolerance
      window. If outside the window, DENY.

8. PERMIT.
~~~

Enforcement points MUST verify the JWS signature of each token before
deserializing its payload claims into application-layer data structures.
Signature verification operates on the raw encoded header and payload
bytes (the JWS Signing Input) and does not require claim parsing. Full
claim parsing MUST NOT occur until after signature verification succeeds
for that token. This ordering prevents parser-based denial-of-service
attacks on maliciously crafted payloads. The sole exception is step 2c:
extracting only the `jti` string field for cycle detection prior to
signature verification is permitted, provided the implementation treats
the extracted value as untrusted until the corresponding signature is
verified. Enforcement points MUST reject any token whose JWS `alg`
header is `"none"`. The `"none"` algorithm provides no cryptographic
protection and MUST NOT be used in any AAT or PoP JWT.

The `hta` comparison in step 7f requires both the enforcement point and
the PoP JWT issuer to use JCS canonicalization ({{RFC8785}}). The
enforcement point MUST canonicalize the `args` map independently and
compare the resulting byte sequence against the canonical form committed
to by the PoP JWT signature. Implementations MUST NOT compare raw JSON
strings; surface differences such as key ordering or numeric
representation (e.g., 1.0 vs 1) are resolved by canonicalization before
comparison.

The JWS `alg` header value MUST be consistent with the key type of the
key used to verify the signature: the trust anchor public key for root
tokens, and the `cnf.jwk` of the parent token for derived tokens.
Enforcement points MUST reject any token where the declared `alg` is not
compatible with the verifying key's `kty` and `crv` parameters. For
example, a token whose `alg` is `"EdDSA"` MUST be verified against an
OKP key with `"crv": "Ed25519"` or `"crv": "Ed448"`. A mismatch between
the declared algorithm and the verifying key type MUST result in denial,
regardless of whether the signature bytes would verify under an
alternate interpretation.


# Security Considerations

## Threat Model

This section characterizes the threats that AATs mitigate and the
threats that are outside the scope of this mechanism. Implementations
SHOULD use this characterization to evaluate whether AATs are sufficient
for their threat environment and to identify what complementary controls
are required.

### Threats Mitigated

**Prompt injection leading to unauthorized tool invocation.** An
attacker who injects instructions into an agent's input cannot cause the
agent to invoke tools outside the scope encoded in its token. The
enforcement point rejects any invocation of an unauthorized tool
regardless of the agent's stated rationale.

**Hallucinated tool invocations with out-of-scope arguments.** Even
when an agent invokes an authorized tool, argument constraints in the
leaf token
restrict the argument values the enforcement point will accept. An agent
that hallucinates an argument value outside the authorized range is
denied at the enforcement point before the tool executes.

**Confused deputy attacks.** A sub-agent that receives a derived token
cannot exercise authority beyond what its token encodes, even if it is
invoked by a trusted orchestrator. The token carries its own
authorization ceiling. There is no ambient authority to confuse.

**Privilege escalation across delegation hops.** The capability
monotonicity invariant (I4) ensures that authority can only narrow at
each delegation step. A derived token cannot authorize tools or
argument values absent from its parent token. An agent that attempts
to mint a derived token with
broader scope will produce a token that fails chain verification at the
enforcement point.

**Compromised sub-agents.** If a sub-agent is compromised, the blast
radius is bounded by the scope of the token it holds. The attacker
cannot use the compromised agent to escalate to broader authority,
invoke tools outside the token's scope, or derive tokens with wider
permissions than the compromised token encodes.

**Grant-context substitution.** The `par_hash` claim (I5) binds each
derived token to the specific bytes of its parent token. Suppose a
delegator key holds two parent tokens, `A` and `B`, issued for different
tasks but authorizing compatible capabilities. The holder derives child
token `C` from `A`. Without `par_hash`, a presenter could assemble the
chain `[B, C]`. The link may satisfy delegation authority, depth,
lifetime, and capability monotonicity: `C` is signed by the key named in
`B.cnf.jwk`, has the expected depth, does not outlive `B`, and
authorizes no capability outside `B`. However, the chain has been
re-associated with task `B` rather than task `A`. The `par_hash` check
rejects this because `C` commits to the signing input of `A`, not
`B`.

**Token replay for irreversible operations.** For irreversible or
side-effecting tool invocations, stateful `jti` tracking at the
enforcement point enables prevention of PoP JWT replay. See Section 8.6
for the distinction between stateful and probabilistic replay controls
and the deployment requirements for each.

### Threats Not Mitigated

**Malicious or compromised root issuer.** The security of all chains
depends on the integrity of the trust anchor key. A root issuer that
mints tokens with overly broad scopes, or whose signing key is
compromised, undermines the authorization guarantees of every chain it
anchors. AATs provide no mechanism to detect or constrain a malicious
root issuer. Key management, rotation procedures, and root issuer
accountability are deployment concerns outside the scope of this
specification.

**Compromised enforcement point.** An enforcement point that skips chain
verification, ignores constraint evaluation, or accepts forged tokens
provides no security guarantee regardless of the token format. AATs
assume enforcement points are honest and implement the verification
algorithm in Section 7 correctly. Enforcement point integrity is a
deployment concern.

**Actions within authorized argument constraints.** AATs restrict which
tools an agent may invoke and what argument values are permitted. They
do not restrict which authorized invocations an agent chooses to make,
in what order, or how many times. An agent that makes excessive or
unintended use of its authorized tools within the bounds of its token is
not detectable at the enforcement point. Rate limiting, audit logging,
and behavioral monitoring are complementary controls for this threat.

**Compromised holder key.** If an agent's private key is stolen, the
attacker can exercise the full authority encoded in that agent's token
until the token expires. The blast radius is bounded by the token scope,
but within that scope the attacker has full authorization. Short token
lifetimes (Appendix B.8) limit the exposure window.

**Model exfiltration and side-channel attacks.** An attacker who
extracts an agent's model weights, system prompt, or in-context state
may be able to predict or manipulate the agent's behavior independently
of its token constraints. AATs operate at the authorization layer and
have no visibility into the model layer.

**Social engineering of the root issuer.** An attacker who convinces the
root issuer to mint a root token with broad scope obtains
broad authority through legitimate token issuance. This is not
detectable by chain verification.

## Attenuation as the Security Invariant

The capability-containment guarantee of this specification rests on
the enforcement of the capability monotonicity invariant (I4). An
enforcement point that fails to check I4, or that checks it
incorrectly, provides no blast radius containment. The broader chain
security properties also depend on the remaining invariants: delegation
authority (I1), depth bounds (I2), lifetime bounds (I3), parent-token
linkage (I5), and proof of possession (I6). Implementers MUST test I4
enforcement against the full constraint attenuation matrix in Section
4.5, including all (parent
type, child type) pairs, and MUST reject all pairs not explicitly
permitted.

Those other invariants rely on well-established
cryptographic primitives and validation patterns with substantial prior
art in deployed systems. I4 is novel. Formal verification of the I4
subsumption rules is in progress, using bounded model checking
({{ALLOY}}) for set-theoretic constraint types and SMT solving ({{Z3}})
for numeric and structural constraint types. Implementers are encouraged
to publish independent analyses of both the core subsumption rules and
any extension constraint types they deploy.

The Tenuo reference implementation includes a test suite covering monotonicity
of the attenuation invariants under arbitrary sequences, normalization
idempotence across encode/decode round-trips, and enforcement agreement
between in-memory and deserialized constraint evaluation. See
Appendix E for implementation status.

## Root Key Compromise

A compromised trust anchor key allows an attacker to issue arbitrary
root tokens. This breaks the security guarantees of all chains anchored
to that key. Deployments SHOULD implement key rotation procedures and
revocation mechanisms appropriate to their risk model. The specific
mechanism for root key revocation, including revocation list formats,
distribution protocols, and enforcement point update procedures, is
outside the scope of this specification.

## Holder Key Compromise

A compromised holder key allows an attacker to present existing tokens
issued to that holder. The attacker cannot derive tokens with broader
scope than the compromised token grants. Mitigation is revocation of
tokens bound to the compromised key, or expiry-based recovery for
short-lived tokens.

## Grant-Context Substitution

The `par_hash` invariant (I5) is the primary defense against
grant-context substitution. Enforcement points MUST verify `par_hash` at
every chain link per step 4q of the verification algorithm (Section 7).

## Replay Attacks

The PoP JWT binds a specific invocation to a nonce, a timestamp, the
target tool, the presented arguments, and, when required by deployment
policy, the enforcement point or resource audience. The timestamp window
limits the interval during which a captured PoP JWT remains usable to
approximately twice the clock tolerance (RECOMMENDED: ±30 seconds,
giving a window of roughly 60 seconds). This provides probabilistic
replay resistance and is appropriate only for idempotent, read-only tool
invocations where duplicate execution is harmless.

For tool invocations that are irreversible or have significant side
effects, including financial transactions, data deletion, writes to
external systems, and any operation that cannot be undone: enforcement
points MUST implement stateful `jti` tracking for PoP JWTs and MUST NOT
rely solely on the timestamp window for replay protection.

PoP JWTs are scoped to the invocation data they contain. Deployments with
multiple enforcement points, resource servers, tenants, or resource
contexts that could accept the same AAT chain SHOULD require the
`aat_aud` claim and reject PoP JWTs whose audience does not identify the
accepting enforcement point or resource. Without audience binding, a PoP
JWT captured at one enforcement point may be replayable at another
enforcement point that accepts the same chain, tool name, and argument
map within the timestamp window, unless stateful `jti` tracking is shared
across those contexts.

This specification requires stateful `jti` tracking for irreversible
operations but does not define the storage backend, consistency model,
or distribution protocol for that state. The required consistency
properties depend on the deployment topology and the risk tolerance of
the application. Deployments SHOULD treat the time-windowed PoP as a
probabilistic control and layer additional idempotency mechanisms at the
application level for high-value operations.

## Constraint Evaluation

The core constraint types are intended to have predictable evaluation
cost. Extension constraint types can introduce parser complexity,
algorithmic cost, normalization requirements, or external policy-engine
dependencies. Extension constraint types registered under Section 3.5
MUST document their computational complexity and any resource limits
implementations SHOULD enforce. Enforcement points SHOULD impose
evaluation timeouts on any extension constraint type whose `check`
predicate is not O(n) in the length of the argument value.

## Depth Limit

Enforcement points MUST enforce a finite MAX_DELEGATION_DEPTH to prevent
resource exhaustion from artificially deep chains. The appropriate value
is deployment-specific: linear orchestration chains require far fewer
hops than swarm architectures with deep fan-out delegation.
Implementations SHOULD choose a value that reflects the maximum chain
depth their deployment topology requires, without imposing an artificial
ceiling on legitimate use cases. See Appendix B.5 for guidance on
selecting an appropriate value.

The security rationale for depth limiting goes beyond resource
exhaustion. Each delegation hop introduces an additional agent into the
trust chain: the enforcement point necessarily trusts not only that the
leaf token holder is honest, but that every intermediate holder made
sound attenuation decisions. A compromised or misdirected intermediate
agent can narrow constraints in ways that serve an attacker's goals
while remaining within the invariants. The depth limit bounds the number
of such trust extensions that a single root grant can produce.

The `del_max_depth` claim in the root token is the root issuer's
explicit policy on chain topology. An implementation that ignores
`del_max_depth` or enforces only a global implementation limit without
checking per-token values violates this policy. Enforcement points MUST
check the per-token depth ceilings (`child.del_depth <=
parent.del_max_depth` in step 4e, `child.del_max_depth <=
parent.del_max_depth` in step 4g, and `child.del_depth <=
child.del_max_depth` in step 4m of Section 7) and the global
MAX_DELEGATION_DEPTH limit (step 4f of Section 7). Neither the per-token
policy checks nor the global implementation limit is sufficient alone.

## Unknown Constraint Types

Enforcement points MUST deny authorization when they encounter an
unknown constraint type. Permitting invocation in the presence of an
unrecognized constraint would silently remove a restriction the issuer
intended to enforce.

## Token Revocation

Revocation of individual AATs, including derived tokens, is outside the
scope of this specification. The offline delegation model trades
per-token revocation granularity for verifiability without authorization
server availability. This is a deliberate design choice, not an
oversight.

Deployments SHOULD use short token lifetimes as the primary recovery
mechanism. A short-lived leaf token provides a bounded damage window that
is operationally equivalent to revocation for most threat models, without
the availability and consistency requirements that a revocation list
imposes. Root tokens SHOULD be issued with the shortest lifetime
compatible with the intended delegation chain depth.

Root trust anchor rotation (replacing the trust anchor signing key and
re-issuing root tokens) is the appropriate response to a root key
compromise. Enforcement points SHOULD support configurable trust anchor
sets to enable rotation without downtime.

Revocation list distribution, token status list integration, and
per-token introspection mechanisms are deferred to a companion document.

## Clock Skew

This specification uses clock-based checks in two distinct contexts with
different semantics. MAX_IAT_SKEW (Section 4.4, RECOMMENDED: 30 seconds)
is a one-sided future-dating tolerance applied to token `iat` values: it
prevents a token issued slightly in the future from being rejected due
to minor clock drift between issuer and enforcement point. The PoP
JWT timestamp window (Section 5.3, RECOMMENDED: ±30 seconds) is a
bilateral replay
window applied to PoP JWT `iat` values: it bounds how long a captured
PoP JWT remains usable. These are independent parameters enforced at
different points in the verification algorithm and SHOULD be configured
separately.

PoP JWT timestamp verification requires synchronized clocks. The
RECOMMENDED tolerance window is ±30 seconds, which accommodates typical
Network Time Protocol (NTP) synchronized deployments with generous
margin. Deployments running on cloud infrastructure with guaranteed NTP
synchronization SHOULD target ±5 to ±10 seconds. Deployments with
stricter security requirements MAY reduce this window further.

Implementations MUST enforce a finite maximum tolerance window. Values
beyond ±60 seconds provide negligible additional clock skew tolerance
while meaningfully expanding the PoP replay window and are NOT
RECOMMENDED. A value of ±30 seconds is the conservative baseline; the
±60 second ceiling is intended only for heterogeneous environments such
as embedded systems or degraded connectivity scenarios.

## Role-Based Key Separation

Deployments that distinguish planning agents from tool-invoking agents
SHOULD use distinct holder keys for
those runtime roles and SHOULD derive across that boundary with a fresh
`cnf.jwk`. This limits the blast radius of a compromised planning
component and preserves operational accountability between components
that decide what work should be done and components that invoke tools.

Role-based key separation is deployment guidance, not a base protocol
invariant. Enforcement points implementing this specification verify the
holder-key chain, attenuation invariants, parent-token linkage, and leaf
PoP proof; they do not infer agent runtime roles from token claims unless
a deployment-specific profile defines such claims and verification rules.

## Algorithm Confusion

AATs are signed JWTs. Implementations are subject to the full class of
JWT algorithm confusion attacks, including `alg: "none"` acceptance,
symmetric/asymmetric key confusion (RS256/HS256 key reuse), and
algorithm substitution across tokens in the same chain.

Enforcement points MUST maintain an explicit allowlist of permitted
signature algorithms and MUST reject any token whose `alg` header value
is not on that list. Implementations MUST reject tokens with `alg:
"none"` unconditionally and MUST NOT treat the absence of an `alg`
header as equivalent to any permitted algorithm.

Implementations MUST apply the algorithm allowlist independently to each
AAT in the chain and to the PoP JWT. Accepting a weaker algorithm on an
intermediate token because the leaf token used a strong algorithm is a
verification failure.

The RECOMMENDED algorithm set is the same as for DPoP {{RFC9449}}:
ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA.
Symmetric algorithms (HS256, HS384, HS512) MUST NOT be used for AAT
signatures; symmetric keys cannot provide the per-holder key binding
that PoP requires.

## Token Content Visibility

AAT payloads are integrity-protected but not encrypted. Token
contents, including tool identifiers, argument constraints, and
delegation chain structure, are visible to any party that observes
the token in transit or at rest. Deployments SHOULD transmit AAT
chains over encrypted transport (e.g., TLS) and SHOULD treat stored
tokens as sensitive material. Token encryption is outside the scope
of this specification.

# IANA Considerations

## JWT Claims Registry

This document requests registration of the following claims in the IANA
JSON Web Token Claims Registry {{RFC7519}}.

**AAT claims:**

| Claim Name | Claim Description | Change Controller | Reference |
|---|---|---|---|
| `del_depth` | Delegation chain depth | IETF | This document |
| `del_max_depth` | Maximum delegation chain depth | IETF | This document |
| `par_hash` | Parent token signing input hash | IETF | This document |

The `tools` map is not a top-level JWT claim; it is a member nested
inside the `authorization_details` array entry with `type:
"attenuating_agent_token"`, as defined in Section 3.3. Its structure and
semantics are governed by the AAT Constraint Type Registry (Section 9.3)
and the RAR profile defined in this document, not by the JWT Claims
Registry.

**PoP JWT claims:**

| Claim Name | Claim Description | Change Controller | Reference |
|---|---|---|---|
| `aat_id` | AAT `jti` being presented | IETF | This document |
| `aat_tool` | Tool identifier for PoP binding | IETF | This document |
| `aat_aud` | Enforcement point or resource audience for PoP binding | IETF | This document |
| `hta` | Tool arguments for PoP binding | IETF | This document |

## OAuth Authorization Details Types Registry

This document requests registration of the following type in the IANA
OAuth Authorization Details Types Registry established by {{RFC9396}}.

| Type Name | Reference |
|---|---|
| `attenuating_agent_token` | This document |

## AAT Constraint Type Registry

This document requests IANA create the "Attenuating Authorization Token
Constraint Types" registry. The registration policy for this registry is
Specification Required {{RFC8126}}.

### Designated Expert Instructions

Designated experts MUST verify that each submitted registration
satisfies all of the following criteria before approving it:

1. The type name is a lowercase string containing only letters,
   digits, and underscores, and does not conflict with an
   existing registered type name.

2. The `check` predicate is fully specified: given any argument
   value, an independent implementer can determine without
   ambiguity whether the predicate returns true or false.

3. The `subsumes` verification procedure satisfies the decidable,
   sound, and deterministic properties defined in Section 3.5.1.
   If the constraint language does not support a general
   containment algorithm, the registration prescribes a
   conservative syntactic strategy and formally justifies
   its soundness.

4. The cross-type subsumption rules enumerate every (parent
   type, child type) pair involving both the new type and
   all existing core types that the registration declares
   valid, with explicit conditions. Unlisted
   pairs are implicitly invalid; the registration MUST NOT rely on the
   catch-all rejection rule to handle pairs that deserve explicit
   treatment.

5. The reference is a stable, publicly accessible document.
   Internet-Drafts that have not yet been published as RFCs
   are not acceptable as stable references.

Designated experts SHOULD request clarification when cross-type rules
are incomplete, when the subsumption procedure's soundness is not
formally justified, or when the check predicate leaves ambiguous cases
unresolved.

### Registration Template

Registration requests MUST use the following template:

~~~
Type name:
  (A lowercase string. Example: "path_containment")

Additional members:
  (List each JSON member name, its JSON type, whether it is required
  or optional, its default value if optional, and its semantics.
  Example: "root (string, required): An absolute path prefix.")

check predicate:
  (A complete, unambiguous specification of the boolean predicate
  evaluated against an argument value at invocation time. Must
  cover all edge cases including null, empty, and out-of-range
  inputs.)

subsumes verification procedure:
  (A complete formal definition of what it means for one instance
  of this constraint type to be at least as restrictive as another.
  Must state whether the procedure is conservative and, if so, which
  semantically subsuming pairs it rejects. Must include a soundness
  argument: if the procedure returns true for (C_parent, C_child),
  then for all values v: C_child.check(v) implies C_parent.check(v).)

cross-type subsumption rules:
  (An explicit enumeration of every (parent type, child type) pair
  involving this type that is a valid attenuation, and the conditions
  under which it is valid. List both directions: this type as parent
  and this type as child. All unlisted pairs are implicitly invalid.
  Example:
    - (exact, this_type): valid if the exact value satisfies this
      type's check predicate.
    - (this_type, exact): invalid.
    - (this_type, this_type): valid if [condition].)

security considerations:
  (Any security properties, limitations, or attack surfaces specific
  to this constraint type, including known cases where the check
  predicate or subsumption procedure can be bypassed or confused.)

reference:
  (A stable, publicly accessible document defining all of the above.)
~~~

### Initial Registry Entries

The core constraint types defined in Section 3.4 of this document
constitute the initial registry entries. For each type, the check
predicate and additional members are defined in Section 3.4, and the
subsumption rules and cross-type pairs are defined in Section 4.5.

| Type Name | Reference |
|---|---|
| `exact` | This document (Sections 3.4, 4.5) |
| `range` | This document (Sections 3.4, 4.5) |
| `one_of` | This document (Sections 3.4, 4.5) |
| `not_one_of` | This document (Sections 3.4, 4.5) |
| `contains` | This document (Sections 3.4, 4.5) |
| `subset` | This document (Sections 3.4, 4.5) |
| `wildcard` | This document (Sections 3.4, 4.5) |
| `all` | This document (Sections 3.4, 4.5) |
| `any` | This document (Sections 3.4, 4.5) |

## OAuth Authorization Server Metadata Registry

This document requests registration of the following parameter in the
IANA OAuth Authorization Server Metadata registry established by
{{RFC8414}}.

| Metadata Parameter | Metadata Description | Change Controller | Reference |
|---|---|---|---|
| `aat_issuer` | Indicates root AAT issuance support | IETF | This document |

`aat_issuer` is a boolean value. When present and `true`, it indicates
that the root issuer supports issuance of AAT root tokens as described
in Section 3.7. When absent, the AS is assumed not to support AAT
issuance.

## OAuth Token Type Registration

This document requests registration of the following token type in the
OAuth Token Type Registry ({{RFC6749}} Section 11.1):

- Type name: `aat`
- Additional Token Endpoint Response Parameters: (none)
- HTTP Authentication Scheme(s): (none; not a bearer token)
- Change controller: IETF
- Specification document(s): This document

## OAuth Parameters Registry

This document makes no request to the OAuth Parameters Registry. Root
token issuance uses the existing `req_cnf` token request parameter.

--- back

# Comparison with Related OAuth Mechanisms (Non-Normative)

## Token Exchange (RFC 8693)

RFC 8693 allows a client to exchange one token for another, potentially
with reduced scope, by contacting the authorization server. The server
enforces scope reduction. This requires network connectivity to the
authorization server at each delegation hop and cannot be performed
offline.

This specification allows a token holder to derive a new token
locally, without contacting the authorization server. The attenuation
invariant is enforced by the chain verification algorithm, not by a
server-side policy check.

## Rich Authorization Requests (RFC 9396)

RFC 9396 defines a structured format for expressing fine-grained
authorization details in OAuth tokens. This specification uses the
`authorization_details` claim format from RFC 9396 and extends it with:
(1) a delegation chain model that links tokens via cryptographic hashes,
(2) monotonic attenuation invariants that constrain what derived tokens
may express, and (3) proof-of-possession binding that ties invocations
to specific key holders.

## DPoP (RFC 9449)

DPoP ({{RFC9449}}) is a token theft prevention mechanism that binds an
existing OAuth access token to a holder key, ensuring that a stolen
token cannot be presented without the corresponding private key. DPoP
does not change what the access token authorizes; the token's
authorization claims are unchanged. The resource server grants whatever
the access token permits; DPoP adds a cryptographic proof that the
presenter holds the bound key.

AATs encode the authorization itself. The token specifies which tools
may be invoked, with what argument constraints, and by which key holder.
Holders can derive tokens with authority equal to or narrower than
their own, without contacting the authorization server. The PoP JWT in
Section 5 serves a similar cryptographic role to a DPoP proof, binding a
specific invocation to the leaf token's holder key, but operates in a
different context. Everything else in this specification (the chain
model, the attenuation invariants, the constraint type registry, the
subsumption matrix) addresses questions outside DPoP's scope.

Structurally, DPoP is a two-party protocol between a client and a
resource server. There is no delegation model, no parent-child chain,
and no attenuation invariant. The chain model of this specification
(`del_depth`, `par_hash`, `del_max_depth`, and the six attenuation
invariants) has no DPoP analog.

At the proof level, DPoP binds to an HTTP method (`htm`) and URI
(`htu`). AAT PoP JWTs bind to a tool name (`aat_tool`) and a structured
argument map (`hta`). Tool invocations are function calls, not HTTP
requests, and a URI alone carries insufficient information for
argument-level constraint evaluation. This is why `aat_tool` and `hta`
differ structurally from `htm` and `htu`: (1) `hta` carries the full
argument map required for constraint evaluation at the enforcement
point; (2) `aat_id` binds the proof to a specific leaf token `jti` and
chain position, for which DPoP has no equivalent.

The cryptographic mechanism is the same: an asymmetric key in `cnf.jwk`,
compact JWT serialization, verified against the leaf token's bound key.
DPoP could in principle be layered alongside AATs as a transport-level
binding for chain delivery, but that combination is outside the scope of
this specification.

## Biscuit

Biscuit {{BISCUIT}} is a capability-based authorization token format
that combines asymmetric public key signatures with offline attenuation,
building on the Macaroons model. Like AATs, Biscuit tokens support
offline derivation and monotonic attenuation: a holder can produce a
more restricted token without contacting the original issuer, and the
resulting token cannot exceed the authority of its parent.

The primary structural difference is the policy language. Biscuit
encodes authorization logic in a Datalog variant that is evaluated at
verification time, requiring a logic engine at the enforcement point.
This enables expressive relational policies but introduces a runtime
dependency and non-trivial computational bounds to manage.

AATs encode authorization as a structured capability map with typed
argument constraints. The core constraint types are decidable by
structural analysis, requiring no logic engine. For cases where
structural constraints are insufficient, the registered extension type
mechanism supports domain-specific matchers and policy-language
constraints with their own defined subsumption procedures. This tradeoff
favors simplicity and predictability at the enforcement point, at the
cost of the relational expressiveness Datalog provides.

A second difference is scope. Biscuit is a general-purpose authorization
token format. It does not natively encode OAuth-oriented delegation-chain
claims such as depth limits, parent-token linkage, or explicit chain
position declarations. This specification defines those properties in the
token model itself, making the chain independently verifiable as a
delegation protocol rather than as a sequence of policy blocks.


# Implementation Notes (Non-Normative)

## Algorithm Recommendations

- **Signing algorithm:** Ed25519 {{RFC8032}}. The normative requirement
  is in Section 3.2. EdDSA provides compact 64-byte signatures suitable
  for constrained agent environments. The JWS `alg` header value for
  Ed25519 is `"EdDSA"`.
- **Key representation:** JWK {{RFC7517}} with `"kty": "OKP"` and
  `"crv": "Ed25519"`.
- **Token identifier:** UUIDv7 is recommended for `jti` values,
  providing time-ordered identifiers without central coordination.

The algorithm allowlist requirement is normatively defined in Section 7
(steps 3a, 4a, and 7a) and discussed in Section 8.13.

Post-quantum migration: the `cnf.jwk` key type is not hardcoded to
Ed25519. Implementations should be designed to support key type
migration. NIST finalized ML-DSA (FIPS 204, formerly Dilithium) in 2024
as a post-quantum digital signature standard. Deployments with long-term
security requirements should design their key management infrastructure
to support algorithm migration without requiring changes to token
structure.

## Performance

Chain verification requires one signature verification per chain link.
Ed25519 verification is computationally lightweight; for typical chain
depths of 3 to 5 links, verification overhead is negligible relative to
network latency in most deployment contexts. Constraint evaluation for
`exact`, `one_of`, `range`, and similar structural types is O(n) in the
number of constraints. Extension constraint types can have higher
evaluation cost; see Section 8.7 for resource limit guidance.

## Recognizing Derived Token `iss` Values in Middleware

In both root and derived AATs, `iss` is a URI. For root tokens it
is a conventional issuer URI. For derived tokens it is a JWK
Thumbprint URI ({{RFC9278}}) with the
`urn:ietf:params:oauth:jwk-thumbprint:sha-256:` prefix.
Middleware that routes or policy-evaluates based on `iss` should
recognize the JWK Thumbprint URI scheme and apply chain-aware
processing rather than attempting to resolve the URI as an issuer
endpoint. The verification key for derived tokens is
`parent.cnf.jwk`, resolved from the preceding chain link.

## Relationship to WIMSE

The WIMSE architecture {{WIMSE-ARCH}} and service-to-service protocol
{{WIMSE-S2S}} address workload identity and authentication for entities
that hold and present AATs. A WIMSE workload credential identifies an
agent; the `iss` claim in a root AAT issued to that agent may reference
the agent's WIMSE workload identifier. The two specifications are
complementary: WIMSE establishes workload identity and authentication;
this specification defines a holder-derivable, invocation-scoped
delegation and attenuation mechanism that WIMSE does not standardize.

## Delegation Depth Guidance

The normative requirement is only that implementations enforce a finite
MAX_DELEGATION_DEPTH. This appendix provides non-normative guidance for
selecting an appropriate value.

The appropriate MAX_DELEGATION_DEPTH depends on the deployment topology.
Linear orchestration chains — root issuer, one or two planning layers,
leaf executor — require few hops. Swarm architectures with dynamic
fan-out, sub-task delegation, or hierarchical agent groups may require
significantly deeper chains. The implementation ceiling should reflect
the maximum depth the deployment actually needs, not an arbitrary
conservative default.

Regardless of the implementation ceiling, issuers should set
`del_max_depth` in individual tokens to the minimum depth the specific
workflow requires. A grant with a lower `del_max_depth` than the
implementation ceiling is always permitted and limits blast radius if a
token is misused. The security value comes from tight per-chain policy,
not from a low implementation ceiling.

## Implementation Size Limits

The normative requirement is only that implementations enforce finite
limits on token size, chain size, constraint nesting depth, and tool
count to prevent resource exhaustion. This appendix provides
non-normative recommended defaults for implementations with no specific
deployment constraints:

| Parameter | Recommended Default |
|---|---|
| Maximum token size | 64 KB |
| Maximum chain size | 256 KB |
| Maximum tools per token | 256 |
| Maximum constraints per tool | 64 |
| Maximum constraint nesting depth | 32 |
| Maximum tool name length | 256 bytes |
| Maximum constraint value length | 4 KB |

Deployments should document their enforced limits. Interoperating
parties should verify that their respective limits are compatible before
deployment.

Implementations should prefer core structural constraints where the
policy permits, as these types produce compact tokens and simple
subsumption checks.

Implementations concerned about parser exposure on unverified
payloads in step 2c of the chain verification algorithm (Section 7)
may extract `jti` using a length-limited byte scan rather than a
full JSON parser, provided the extraction correctly handles JSON
whitespace and string escaping.

A single AAT is typically 1-4 KB when base64url-encoded. Chains
of two or more tokens will commonly exceed the 4-8 KB header size
limits enforced by common reverse proxies and load balancers,
resulting in 431 errors. Deployments should transmit AAT chains
in a request body field rather than an HTTP header. For
size-constrained environments, the CBOR/CWT considerations in Appendix D
describe representations that can reduce chain size by 30-50% and are
recommended when HTTP header transport is required.

## Signed Passthrough Metadata

Deployments may need to convey additional signed metadata through the
delegation chain, such as a request trace identifier, a tenant context
used for logging or routing, or a human-readable subject identifier.
This specification does not define a mechanism for such metadata, but
the JWT format accommodates it naturally.

Implementations may include additional JWT claims in AATs beyond those
defined in Section 3. Claims used for passthrough metadata should use
collision-resistant names (e.g., reverse domain notation such as
`com.example.trace_id`) and should not encode tool permissions or
argument constraints that this specification models in
`authorization_details`.

Because additional claims are included in the token's JWS signature,
they are integrity-protected within each individual token. However,
this specification's chain verification algorithm (Section 7) does not
enforce preservation of unrecognized claims across derivation steps.
Per Section 3.4, enforcement points ignore unrecognized top-level JWT
claims; the fail-closed rule applies only to constraint types within
`authorization_details`. A token carrying a `com.example.trace_id`
claim will not be rejected solely for containing that claim.
Deployments that require chain-wide preservation of passthrough
metadata must define and enforce their own derivation and verification
rules for those claims, either through deployment-specific policy or
in a companion profile.

## TTL Guidance

The normative requirement is only that derived tokens cannot outlive
their parents and that token lifetime does not exceed MAX_TOKEN_LIFETIME
(Section 4.4). This appendix provides non-normative guidance for
selecting appropriate TTL values.

TTL is the primary revocation mechanism in this specification. A token
that has expired cannot be used regardless of whether a revocation list
exists. Short lifetimes reduce the window of exposure from key
compromise, token theft, or scope misconfiguration. The operational cost
of short TTLs is re-issuance frequency; this cost is low when the root
issuer is available and derivation is offline.

The appropriate TTL depends on the token's position in the chain and the
deployment context. Root tokens should be long enough to cover the full
orchestration and execution window for the task, but no longer. Leaf
tokens should be scoped to the expected duration of a single tool
invocation. Deployments with intermittent connectivity (edge, embedded,
or air-gapped) may need longer lifetimes, with the awareness that longer
lifetimes expand the compromise window.

Deployments should treat TTL as a policy expression rather than a
convenience parameter. A root token with a 24-hour TTL
effectively grants the holder 24 hours of authority regardless of how
narrowly the capability scope is defined.


# Policy Languages with Decidable Containment (Non-Normative)

This appendix provides non-normative guidance for implementers
considering extension constraint types that use structured policy
languages.

The core constraint set is intentionally limited to structural
constraint types with deterministic subsumption rules. This keeps the
base protocol small and predictable, but it also limits expressiveness:
domain-specific matchers and richer policy languages need extension
constraint registrations that define their own `check` and `subsumes`
procedures.

Implementers requiring richer policy expressiveness without sacrificing
subsumption decidability should consider languages that were designed
specifically for authorization use cases and that provide formal
containment algorithms as a first-class operation. Such languages are
better positioned to provide conforming extension constraint
registrations under Section 3.5.1, because their containment algorithms
are decidable and formally verified rather than approximated by
conservative syntactic rules.

For example, a future extension could profile an analyzable
authorization policy language such as Cedar {{CEDAR}} as an AAT
constraint type. Such a profile would need to define the runtime
`check` predicate, the token encoding of the policy, and a sound,
deterministic subsumption procedure. The fact that a policy language can
decide whether an invocation is authorized is not, by itself, sufficient
for AAT attenuation; the extension must also define how an enforcement
point determines that a derived policy is no less restrictive than its
parent.

The key property to look for is whether the language's policy
containment problem ("does every input permitted by policy A also
satisfy policy B?") is decidable and implemented in available tooling.
Languages with this property allow a registration to specify a
subsumption verification procedure that is both decidable and
non-conservative: it returns true for all semantically subsuming pairs,
not just syntactically obvious ones.

This document takes no position on which specific policy language
implementers should choose. The choice depends on the deployment
environment, existing infrastructure, tooling availability, and the
specific authorization semantics required. The normative requirement is
only that whatever language is used, the resulting extension constraint
registration satisfies the three properties defined in Section 3.5.1:
decidable, sound, and deterministic.

# CBOR/CWT Considerations (Non-Normative)

The claim semantics, attenuation invariants, constraint subsumption
rules, and chain verification algorithm defined in this document are
format-agnostic. They describe a protocol, not an encoding. JWT/JWS is
the only fully specified token encoding in this document. This appendix
notes the relationship to CBOR-based token formats for implementers
operating in constrained or throughput-sensitive environments. A fully
interoperable CWT/COSE encoding, including CWT claim key assignments,
COSE algorithm requirements, the CWT parent token signing input used for
`par_hash`, and CWT-specific serialization rules, is deferred to a
companion document.

This appendix does not define a CWT serialization, CWT claim-key mapping,
COSE algorithm profile, or CWT `par_hash` signing input.

## CWT Representation

CBOR Web Tokens {{RFC8392}} and COSE message signing {{RFC9052}} are the
IETF-native binary analogs of JWT and JOSE respectively. A future CWT
profile could represent the semantic content of an AAT without changing
the attenuation model. The attenuation invariants in Section 4 apply at
the semantic level. A CWT profile would apply the chain verification
algorithm in Section 7 by substituting COSE_Sign1 verification for JWS
signature verification and by defining the CWT parent token signing input
used for `par_hash` computation.

CBOR encoding offers meaningful size advantages over base64url-encoded
JSON for token payloads. In typical AAT payloads with several constraint
entries, CBOR encoding reduces token size by 30-50% relative to compact
JWT serialization. For high-throughput agent pipelines or
resource-constrained edge deployments, this difference is operationally
significant.

## Deterministic Encoding

A future CWT profile will need deterministic CBOR encoding as defined in
{{RFC8949}} Section 4.2. Deterministic encoding requires that integer
keys be used for all map entries where assignments exist, that map keys
be sorted in length-first, bytewise lexicographic order, and that the
shortest-form encoding be used for all values. This ensures that two
interoperating implementations produce identical byte sequences for the
same AAT payload, which is required for correct `par_hash` computation
and cross-implementation chain verification.

The `hta` map within a CWT PoP token likewise needs deterministic CBOR
encoding. A CWT profile should prohibit indefinite-length encoding for
any AAT or PoP token structure.

## Claim Key Assignments

JWT uses string claim names. CWT uses integer claim keys for registered
claims to achieve compact encoding. The AAT-specific claims defined in
Sections 3 and 5 — namely `del_depth`, `del_max_depth`,
`par_hash`, `aat_tool`, `aat_aud`, `hta`, and `aat_id` — require integer key
assignments in the IANA CWT Claims Registry {{RFC8392}} before
a normative CWT profile can be published.

Those registrations, along with COSE algorithm guidance and CWT-specific
serialization rules, are deferred to a companion Internet-Draft. That
document will reference {{RFC8392}} and {{RFC9052}} normatively; this
document references them informatively. This document makes no CWT claim
key assignments.

# Implementation Status (Non-Normative)

This appendix describes the implementation status of this specification
at the time of submission, per the practice described in RFC 7942.

## Reference Implementation

Tenuo provides a reference implementation of this protocol. The chain
verification algorithm (Section 7) and token derivation procedure
(Section 6) are both implemented. Tenuo also includes an
implementation-specific CBOR/COSE wire representation, with Ed25519
signatures carried in COSE_Sign1 structures. That implementation
experience supports the format independence of the core protocol model,
but does not define a fully interoperable CWT profile; the CWT profile is
deferred as described in Appendix D.

RFC Editor Note: Implementation attribution will be updated
or removed prior to WG adoption per IETF norms.

## Formal Verification

Formal verification of the attenuation algebra is in progress, using
three complementary techniques: bounded model checking ({{ALLOY}}) for
set-theoretic constraint types, SMT solving ({{Z3}}) for numeric and
structural constraint types, and property-based testing against the Rust
implementation for implemented constraint types.
Bounded model checking has found no counterexamples for scopes up to 8
constraints and 8 values. The combination is intended to provide
evidence toward monotonicity of the I4 invariant across the full
constraint attenuation matrix.

RFC Editor Note: Implementation details will be updated or
removed per IETF norms prior to publication.
