---
title: Attenuating Authorization Tokens for Agentic Delegation Chains
abbrev: Attenuating Agent Tokens
docname: draft-niyikiza-oauth-attenuating-agent-tokens-02
category: std
consensus: true
submissiontype: IETF
ipr: trust200902
area: Security
workgroup: Web Authorization Protocol (OAuth)
date: 2026-09-29

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
  RFC8725:   # JSON Web Token Best Current Practices
  RFC7800:   # Proof-of-Possession Key Semantics for JWTs
  RFC8032:   # EdDSA
  RFC9864:   # Fully-Specified Algorithms for JOSE and COSE
  RFC8785:   # JSON Canonicalization Scheme (JCS)
  RFC9278:   # JWK Thumbprint URI
  RFC9396:   # Rich Authorization Requests
  RFC9562:   # Universally Unique IDentifiers (UUIDs)
  RFC6749:   # OAuth 2.0 Authorization Framework
  RFC9201:   # OAuth Parameters for ACE
  RFC8414:   # OAuth 2.0 Authorization Server Metadata
  RFC8126:   # Guidelines for Writing an IANA Considerations Section

informative:
  RFC2693:   # SPKI Certificate Theory
  RFC8259:   # The JavaScript Object Notation (JSON) Data Interchange Format
  RFC8792:   # Handling Long Lines in Content of Internet-Drafts and RFCs
  RFC7942:   # Improving Awareness of Running Code: The Implementation Status Section
  RFC8949:   # Concise Binary Object Representation (CBOR)
  RFC8392:   # CBOR Web Token (CWT)
  RFC8693:   # OAuth 2.0 Token Exchange
  RFC9052:   # CBOR Object Signing and Encryption (COSE)
  RFC9334:   # Remote ATtestation procedureS (RATS) Architecture
  RFC9449:   # DPoP
  RFC8707:   # Resource Indicators for OAuth 2.0
  OIDC.Core:
    title: "OpenID Connect Core 1.0 incorporating errata set 2"
    author:
      - name: Nat Sakimura
      - name: John Bradley
      - name: Michael B. Jones
      - name: Breno de Medeiros
        ins: B. de Medeiros
      - name: Chuck Mortimore
    date: 2023
    target: https://openid.net/specs/openid-connect-core-1_0.html
  OAUTH-TXN-TOKENS:
    title: "Transaction Tokens"
    target: https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
    author:
      - name: Atul Tulshibagwale
      - name: George Fletcher
      - name: Pieter Kasselman
    date: 2026-03
  OAUTH-ID-CHAINING:
    title: "OAuth Identity and Authorization Chaining Across Domains"
    target: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/
    author:
      - name: Arndt Schwenkschuster
      - name: Pieter Kasselman
      - name: David Burgin
      - name: Mike Jenkins
      - name: Brian Campbell
      - name: Aaron Parecki
    date: 2026-05
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
  MCP:
    title: "Model Context Protocol Specification"
    author:
      - org: Model Context Protocol
    target: https://modelcontextprotocol.io/specification
  A2A:
    title: "Agent2Agent (A2A) Protocol Specification"
    author:
      - org: A2A Project
    target: https://a2a-protocol.org/latest/specification/
  AAT-VECTORS:
    title: "AAT JWS test vector suite (JSON)"
    author:
      - org: Tenuo
    target: https://github.com/tenuo-ai/tenuo/blob/main/tests/vectors/aat-jws-vectors.json
  AAT-VECTOR-GEN:
    title: "AAT JWS test vectors: readable companion and generator"
    author:
      - org: Tenuo
    target: https://github.com/tenuo-ai/tenuo/tree/main/ietf/vectors
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

--- abstract

This document defines Attenuating Authorization Tokens (AATs), a signed
credential format for task-scoped delegation in AI agent systems. An AAT
encodes the tools an agent may invoke and the argument constraints that
apply to those invocations. A token holder authorized to delegate can
derive a token offline with equal or narrower authority, subject to the
parent token's depth and lifetime limits. The resulting delegation chain
is verifiable offline by any enforcement point that has the root
issuer's trust anchor key.

This specification profiles the OAuth Rich Authorization Requests format
(RFC 9396) for tool-level capability claims, adds delegation-chain
claims, and defines a core constraint vocabulary for argument
restrictions. The chain verification algorithm authenticates each
delegation step and enforces monotonic attenuation without network
contact with the root issuer.

--- middle

# Introduction

AI agent systems increasingly decompose a user request into delegated
steps performed by multiple agents, services, or tools. Each step may
need authority derived from the user or an originating service, but
rarely needs the full authority available to the workflow as a whole.

A token broad enough to support a multi-step workflow can carry more
authority than an intermediate agent needs for its current step. Prompt
injection, model hallucination, or compromise can then exercise that
excess authority. Attenuation limits this exposure by letting each
delegation step pass onward only the authority needed for the next step.

Existing OAuth mechanisms can scope tokens to principals, resources,
APIs, or authorization details, but they do not define an offline,
holder-derivable delegation chain in which each downstream holder can
attenuate authority and any enforcement point can verify that the
resulting token is no broader than its parent. In particular, OAuth does
not define a standard way for a token holder to derive a token that
cryptographically constrains a receiving agent to specific tools and
argument values for a specific task. Section 1.1 explains why Token
Exchange {{RFC8693}} and Rich Authorization Requests {{RFC9396}} do not
fill this gap.

AATs apply the capability model {{DENNIS66}} to OAuth-based agent
systems. Authority travels in unforgeable tokens scoped to specific
operations; a holder can attenuate a token before passing it on but
cannot amplify it {{SALTZER75}} {{MILLER06}}. Enforcement points verify
the leaf token and the delegation path that produced it offline, so the
authorization server is not a participant in each hop. That matters for
agentic workflows that invoke tools in rapid succession, cross trust
boundaries, or run with intermittent connectivity. AATs add this
delegation and attenuation layer to OAuth 2.0 {{RFC6749}} token issuance
and scoping and to WIMSE {{WIMSE-ARCH}} workload identity; they replace
neither.

The same structure addresses a distinct problem, the confused deputy
{{HARDY88}}: a deputy that combines a caller-supplied resource
designation with the deputy's own standing authority can be induced to
perform an action the caller could not perform directly. Capability
systems address this by carrying designation and authority together in
an unforgeable artifact. AATs apply that pattern to agentic delegation:
the invoker can derive a token whose tool and argument constraints
designate the task's resource and authority, and the agent acts under
that received token rather than under ambient authority of its own. AATs
make this possible but do not force it: an agent that also holds a
broader token can still act under that one. Deployments get the benefit
by giving each agent only the token derived for its task, under its own
holder key (Section 9.11); Section 9.1 describes the resulting
guarantees and limits.

An AAT combines four mechanisms that the rest of this document builds
on:

- **Capabilities as claims.** A profile of Rich Authorization Requests
  (RAR) `authorization_details` lists the tools a holder may invoke and
  typed constraints on each argument (Section 3).
- **Attenuation invariants.** A holder derives a child token offline,
  and the child can only narrow tools, argument constraints, delegation
  depth, and lifetime (Section 4).
- **Chain linkage.** Each child is signed by the key its parent names in
  `cnf.jwk` and carries a hash of its parent, so the chain verifies back
  to a trust anchor without contacting the issuer (Sections 4.2 and
  4.6).
- **Holder binding.** Every token names a holder key, and each tool
  invocation carries a PoP JWT signed by the leaf holder over the tool
  and its exact arguments (Sections 3.2 and 7).

Root tokens are issued at an OAuth token endpoint and later tokens are
derived locally (Section 6); an enforcement point verifies the chain and
the proof in one algorithm (Section 8).

The following diagram shows the delegation flow this specification
enables:

~~~
Root Issuer
       |
       | issues root AAT (Section 6.1)
       v
Orchestrating Agent
       |
       | derives AAT (Section 6.2)
       v
Planning Agent
       |
       | derives AAT (Section 6.2)
       v
Tool-Invoking Agent
       |
       | presents AAT with PoP JWT (Section 7)
       v
Enforcement Point
  (verifies chain offline, Section 8)
~~~

At each derivation step, authority can stay the same or narrow, but
never widen. This document defines the token format, derivation, proof
of possession, the presentation an enforcement point receives (Section
7.4), and verification. It leaves four things to deployments or
companion specifications: token revocation, which would reintroduce the
online dependency that offline verification avoids (Section 9.8); a CBOR
encoding (Appendix D); and where a presentation is carried, since agent
frameworks carry tool calls over different protocols, for example MCP
{{MCP}}, A2A {{A2A}}, or plain HTTP, and each needs its own binding;
and how a user's authority, obtained for example through an
authorization code grant with consent, is reflected in a root token.

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
each grant independently, and RFC 8693 does not define a token-local
mechanism for proving that downstream delegation intent remains
consistent with the original authorization scope.

Rich Authorization Requests (RAR) {{RFC9396}} extend OAuth tokens with
structured authorization detail objects, enabling expressive capability
descriptions. RAR addresses the expressiveness problem. It does not
define how a token holder can produce a narrower token, or how a
chain of such derivations can be verified; AATs profile RAR for
tool-level claims (Section 3.3) and add both.

Proposals to extend the authorization code flow with explicit agent
consent, such as introducing a `requested_actor` parameter at the
authorization endpoint, address who the agent is and whether the
user approved the delegation. They do not constrain which tools the
agent may invoke or with what argument values. AATs are
complementary: they scope authority to specific tools and arguments
after identity and consent have been established.

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

4. **Verifiable attenuation.** A derived token cannot grant broader
   authority than its parent, and this property can be verified from the
   signed chain.

5. **JWT/JWS interoperability.** The primary encoding specified in this
   document represents AATs as signed JWTs {{RFC7519}} using JWS
   {{RFC7515}}, allowing deployments to verify chains using existing
   JSON Object Signing and Encryption (JOSE) infrastructure without new
   cryptographic dependencies.

## Relationship to Prior Work

Macaroons {{MACAROONS}} introduced the concept of attenuating tokens
with contextual caveats. Macaroons use HMAC chaining, which provides
attenuation but not proof of possession, and express caveats as
free-form predicates evaluated at the target service at runtime. HMAC
chaining also requires the verifier to hold, or to reach a service that
holds, the root secret. AATs target enforcement points that are not the
root issuer and that may sit in another trust domain, so verification
must succeed against the root issuer's public key alone, with no shared
secret and no call back to the issuer. AATs therefore use asymmetric
signatures and proof of possession, and replace free-form caveats with
typed constraints whose attenuation any party can check structurally
(Section 4.5). Section 9.4 discusses what is lost relative to HMAC
chaining.

SPKI/SDSI {{RFC2693}} defines public keys as principals, delegation
certificates whose effective authority is the intersection of the
authority along the chain, and attenuation by reduction of a tag.
AAT's `cnf.jwk` holder binding, chain verification against a root
key, and the subsumption relation in Section 4.5 correspond to those
three mechanisms, expressed over JWT claims and a typed constraint
vocabulary rather than S-expression tags.

Biscuit {{BISCUIT}} extends the Macaroons model with public-key
signatures and offline attenuation. Biscuit expresses authorization
policies in a Datalog variant, requiring a logic engine at verification
time, and it is commonly used as a bearer credential. This
specification uses structured constraint types decidable by structural
analysis, and encodes in the token model the delegation-chain claims
Biscuit does not natively carry (depth limits, parent-token linkage,
chain position), together with holder-bound invocation-time proof of
possession and attenuation invariants.

Recent OAuth work on transaction tokens {{OAUTH-TXN-TOKENS}} and
identity and authorization chaining {{OAUTH-ID-CHAINING}} addresses the
propagation of identity, actor, transaction, and authorization context
across service and trust-domain boundaries. AATs are complementary: they
define token-local, holder-derivable attenuation of concrete
tool-and-argument authority within a delegation chain, with offline
verification by the enforcement point.

Recent work argues that safe agent delegation needs an explicit,
bounded transfer of authority at each step {{DEEPMIND26}}, and that
capability controls enforced at the tool boundary can defend against
prompt injection {{CAMEL25}}; AATs provide such controls at the
protocol layer.

Appendix A relates the proof-of-possession mechanism to DPoP
{{RFC9449}}. Changes from the previous revision are listed in Appendix
G.


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
In the token endpoint profile of Section 6.1, the root issuer is an
OAuth authorization server (AS).

**Presentation:** The chain and PoP JWT that a presenter sends to an
enforcement point for one tool invocation (Section 7.4).

**Binding:** A specification of how presentations are carried over a
particular protocol, such as MCP or HTTP. Bindings are outside the
scope of this document.

**Presenter:** The party that presents a chain and a PoP JWT to an
enforcement point. An invocation is authorized only when the presenter
is the holder of the leaf token.

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
are compared as exact strings; see Section 3.3.1 for requirements.

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
argument constraints, and permits or denies execution. In OAuth terms,
it plays the role of a resource server for the tools it guards.

**Trust Anchor:** A public key, bound to the issuer identifier of the
root issuer that holds the corresponding private key, that enforcement
points are configured to trust as the root of a delegation chain. Root
tokens are signed by the private key corresponding to a trust anchor.

**Proof of Possession (PoP):** A cryptographic demonstration that the
presenter of a token controls the private key corresponding to the
public key bound in the token's `cnf` claim. In this specification, the
holder of the leaf token signs the PoP JWT with the private key
corresponding to the leaf token's `cnf.jwk`.


# Token Structure

## Chain Position and Invocation Semantics

This specification does not define separate token types for delegation
and execution. An AAT's role is determined by its position in the
presented chain.

The root token establishes the authority ceiling. Intermediate tokens
record attenuations made by holders along the delegation path. The leaf
token is the token whose holder presents a PoP JWT and whose capability
claims are evaluated against the requested tool invocation.

A holder of any AAT MAY derive a child token when `del_depth` is
strictly less than `del_max_depth`. The derived token MUST carry
authority equal to or narrower than the parent token, as enforced by the
capability monotonicity invariant (I4, Section 4.5). A token MUST NOT be
accepted for a tool invocation except as the leaf of a successfully
verified chain.

## Common Claims

The following claims appear in all AATs. All claims listed as
REQUIRED MUST be present. Claims listed as OPTIONAL MAY be omitted;
their absence carries the semantics described in the table.

| Claim | Type | Required | Description |
|---|---|---|---|
| `jti` | string | REQUIRED | Unique token identifier. SHOULD be a UUIDv7 value. When a UUID is used, it MUST be encoded as a lowercase hyphenated string in the form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` per {{RFC9562}}. |
| `iss` | string | REQUIRED | Identifier of the entity that signed this token. For root tokens, MUST be a URI identifying the root issuer. For derived tokens, MUST be a JWK Thumbprint URI ({{RFC9278}}) over the signing key using SHA-256; the exact URI form is given after this table. |
| `iat` | NumericDate | REQUIRED | Time at which the token was issued. MUST NOT be more than MAX_IAT_SKEW in the future relative to the enforcement point's clock (see Section 4.4). In a chain, a derived token's `iat` MUST NOT be earlier than its parent's `iat`. |
| `exp` | NumericDate | REQUIRED | Time at which the token expires. MUST be greater than `iat`. MUST NOT exceed `iat` plus MAX_TOKEN_LIFETIME (see Section 4.4). |
| `cnf` | object | REQUIRED | Confirmation claim {{RFC7800}}. MUST contain `jwk` with the holder's public key. The `jwk` value MUST be a public key; private key material MUST NOT appear in this field. |
| `aud` | string or array of strings | OPTIONAL | Audience, with the semantics of {{RFC7519}} Section 4.1.3: the enforcement points at which this token, and every token derived from it, may be presented. A holder that knows where a token will be presented SHOULD set `aud` when deriving it, in the manner of a contextual caveat {{MACAROONS}} or a resource indicator {{RFC8707}}; a holder that does not know leaves `aud` unset, since a wrong value makes the token and every token derived from it unusable where it is actually presented. Every token in a chain that carries `aud` is checked against the enforcement point (Section 8, step 6c), so a derived token can add or narrow an audience restriction but cannot remove one. |
| `del_depth` | integer | REQUIRED | Delegation depth. 0 for root tokens. Incremented by exactly 1 at each derivation step (see Section 4.3). |
| `del_max_depth` | integer | REQUIRED | Maximum delegation depth permitted in this chain. MUST be a non-negative integer not exceeding the implementation's MAX_DELEGATION_DEPTH (Section 4.3). |
| `par_hash` | string | MUST (derived) / MUST NOT (root) | Base64url-encoded SHA-256 digest of the parent token signing input, using base64url encoding without padding as defined in {{RFC7515}} Appendix C. For JWT/JWS AATs, the parent token signing input is the JWS Signing Input. MUST be absent in root tokens. MUST be present in all derived tokens. |
| `authorization_details` | array | REQUIRED | Tool capability claims. Format defined in Section 3.3. |

Implementations MUST support Ed25519 {{RFC8032}}, JWS `alg` value
`"Ed25519"` ({{RFC9864}}), for token signing and verification.
Implementations MAY support additional asymmetric algorithms
(Section 9.12).

In AATs and PoP JWTs, NumericDate values and the integer claims
`del_depth` and `del_max_depth` are JSON numbers with no fraction or
exponent part. An `aud` value, or a PoP JWT's `aat_aud` (Section 7.2),
identifies an enforcement
point when it is identical, by exact string comparison, to an audience
identifier configured at that enforcement point.

In both root and derived tokens, `iss` is a URI. For root tokens,
`iss` is a URI identifying the root issuer, consistent with
conventional OAuth usage. For derived tokens, `iss` is a JWK
Thumbprint URI {{RFC9278}} of the form
`urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>`, where
`<thumbprint>` is the SHA-256 JWK thumbprint ({{RFC7638}}) of the
signing key. This makes I1 verifiable offline: the enforcement
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
claims outside this specification (see Appendix B.6).

## Capability Claims via `authorization_details`

This specification profiles {{RFC9396}} for tool-level capability
claims. An AAT capability entry is an `authorization_details` entry
whose `type` is set to `"attenuating_agent_token"`. Such an entry MUST
include a `tools` member that maps tool identifiers to constraint maps.

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

Enforcement points check every invocation against its tool's constraint
map in closed-world mode (Section 8, step 6b): an argument the map does
not name MUST be rejected unless the map carries the `"*"` entry
described below, and a named argument absent from the invocation MUST be
rejected unless its constraint is optional. An empty map is shorthand
for `"*"`, so it admits any argument. The presence of a constraint
asserts that the issuer has reasoned about that argument; an invocation
that omits a required one has not been validated against that reasoning.
To authorize an argument without restricting its value while keeping the
map closed, the issuer names it with a `wildcard` constraint (Section
3.4).

**Optional arguments.** A top-level entry in a constraint map MAY carry
the member `optional` with the boolean value `true`. The argument may
then be omitted; when present, it MUST satisfy the constraint.
`optional` defaults to `false` and MUST NOT appear on a constraint
nested inside `all` or `any`. Subsumption (Section 4.5) compares
constraints without this member; Section 4.5 states separately how it
attenuates.
An omitted argument takes the tool's own default, which the enforcement
point cannot see, so issuers mark an argument optional only when that
default is acceptable (Section 9.13).

**Unnamed arguments.** The reserved key `"*"` in a constraint map gives
the constraint for every argument the map does not name. In this
specification its value MUST be a `wildcard` constraint without an
`optional` member, so `"*"` permits arguments the issuer did not name,
with any value. An empty constraint map is equivalent to `{"*":
{"constraint_type": "wildcard"}}`, and enforcement points treat it that
way (Section 8, steps 4p and 6b). The key `"*"` does not name a tool
argument; a tool argument literally named `"*"` is treated as unnamed.
Because `"*"` admits any argument the tool accepts, including arguments
added in later versions of the tool, issuers SHOULD NOT use it for tools
with side effects (Section 9.13).

For example, the following entry pins `path`, bounds the optional
`head` and `tail` line counts without requiring them, and permits any
other argument:

~~~json
{
  "https://tools.example.com/fs/read_text_file": {
    "path": { "constraint_type": "exact",
              "value": "/srv/api/README.md" },
    "head": { "constraint_type": "range", "max": 200,
              "optional": true },
    "tail": { "constraint_type": "range", "max": 200,
              "optional": true },
    "*": { "constraint_type": "wildcard" }
  }
}
~~~

The `authorization_details` array MAY contain entries of other types
alongside `attenuating_agent_token` entries, consistent with the
extensibility model of {{RFC9396}}. Enforcement points implementing this
specification process only entries with `type` set to
`attenuating_agent_token` and MUST ignore entries of other types. An
`authorization_details` array containing multiple entries with `type:
"attenuating_agent_token"` is invalid; the tools map in a single entry
provides sufficient structure for all tool-level capability claims.

Only the `attenuating_agent_token` entry is attenuated by derivation.
Any holder can add or change other claims and other
`authorization_details` entries in a token it derives, so a consumer
MUST NOT derive authority from them in a derived token unless a profile
defines how they attenuate.

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

Tool identifiers are compared as exact strings. Enforcement points MUST
NOT apply Unicode normalization, URI normalization, case folding,
percent decoding, or alias resolution when matching tool identifiers in
the token, the PoP JWT, and the requested invocation. This rule applies
only to tool identifier matching. Argument values are evaluated
according to the semantics of their constraint type; a registered
constraint type MAY define normalization as part of its `check` or
`subsumes` procedure.

Tool identifiers SHOULD be URIs ({{RFC3986}}). URI-format identifiers
provide namespace isolation across agents and reduce semantic collision
when multiple agents expose tools with identical local names.
Deployments spanning multiple agents or trust domains SHOULD use
URI-format identifiers; single-agent deployments MAY use local
identifiers where collision is not a concern.

A tool identifier carries no inherent authorization semantics beyond
naming a capability. The root issuer is responsible for verifying that
requested tools are recognized and that the requester is authorized to
receive authority for them before minting a root token (Section 6.1.3).

## Argument Constraints

Each argument constraint is an object with a `constraint_type` member
and type-specific members. The following constraint types are defined
normatively. The `check` predicate and `subsumes` relation for each type
are normative and fully determined: independent implementations
evaluating either against the same inputs produce identical results.

The core constraint set is intentionally limited to constraint types
with simple, deterministic, format-independent `check` and `subsumes`
rules. Domain-specific matchers and policy-language constraints, such as
resource-identifier matchers, URI or path normalization rules, or
authorization policy expressions, are not core constraint types. They
MUST be defined as registered extension constraint types (Section 5;
see Appendix C for policy languages). The registration process confirms
that the extension defines an unambiguous runtime `check` predicate and
a decidable, sound, and deterministic `subsumes` procedure.

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

Constraint values and arguments are compared by their JCS serializations
({{RFC8785}}), the same canonical form used to compare a PoP JWT's
arguments with the invocation (Section 8, step 7f); `contains` and
`subset` treat their arrays as sets.

JCS serializes a number through its IEEE 754 double-precision value
({{RFC8785}} Section 3.2.2.3), so distinct JSON numbers can share a
canonical form: `9007199254740993` and `9007199254740992` both serialize
as `9007199254740992`. A tool that reads the original text would then
act on a value no constraint evaluated. A JSON number is admissible
when the JCS serialization of its double-precision value denotes the
same number as the text it was parsed from: `0.1`, `1e20`, and
`9007199254740994` are admissible; `9007199254740993` and
`1.00000000000000001` are not. Arguments and constraint values MUST
contain only admissible numbers. The check needs the number as written:
once parsed into a double, the lost digits cannot be recovered. Values
that need more precision, such as large identifiers, are carried as
strings.

A constraint is well-formed when:

- it has no members other than `constraint_type`, `optional`, and the
  members its type defines (the table above, or the type's registration
  for an extension type);
- `exact.value` is a string, number, boolean, or null, and the
  `constraints` member of `all` and `any` is an array;
- `one_of.values` is a non-empty array, and `excluded`, `required`, and
  `allowed` are arrays;
- in a `range`, `min` and `max` are numbers, `min` is not greater than
  `max`, and `min_inclusive` and `max_inclusive` are booleans present
  only with the corresponding bound;
- every number in it is admissible (above); and
- `optional`, where present, is a boolean on a top-level constraint-map
  entry, and a `"*"` entry is a `wildcard` constraint with no `optional`
  member (Section 3.3).

Enforcement points MUST reject a token containing a constraint that is
not well-formed (Section 8, steps 3n and 4o).

Enforcement points MUST reject invocations where any argument violates
its associated constraint. Enforcement points MUST deny authorization if
they encounter a `constraint_type` they do not recognize (fail-closed
behavior): an unrecognized constraint is a restriction the issuer
intended, and skipping it would remove that restriction. This
fail-closed rule applies only to constraint types within
`authorization_details`. Enforcement points MUST ignore unrecognized
top-level JWT claims; a token MUST NOT be rejected solely because it
contains claims outside those defined in this specification.

Composite constraint types (`all`, `any`) are recursive.
MAX_CONSTRAINT_DEPTH is an implementation-defined finite integer
specifying the maximum nesting depth of a constraint tree. A constraint
other than `all` or `any` has depth 1; an `all` or `any` has depth one
more than its deepest clause.
Implementations MUST enforce a finite MAX_CONSTRAINT_DEPTH to prevent
resource exhaustion from pathologically deep constraint trees. A value
of 32 is RECOMMENDED. Enforcement points MUST reject any constraint tree
whose nesting depth exceeds MAX_CONSTRAINT_DEPTH.

## JWS Protected Header

AATs are compact-serialization JWTs {{RFC7519}} signed as JWS
{{RFC7515}}. The JWS Protected Header of every AAT MUST contain:

| Header Parameter | Required | Description |
|---|---|---|
| `alg` | REQUIRED | Signature algorithm. MUST be on the enforcement point's allowlist (Section 9.12). |
| `typ` | REQUIRED | JWT type. MUST be `aat+jwt`. |

The JWS Protected Header of every PoP JWT MUST contain `alg` as above
and MUST contain `typ` set to `aat-pop+jwt`.

Enforcement points MUST reject an AAT whose `typ` is absent or is not
`aat+jwt`, and MUST reject a PoP JWT whose `typ` is absent or is not
`aat-pop+jwt`. Explicit typing follows {{RFC8725}} Section 3.11. It
prevents an AAT from being accepted where a PoP JWT is required, and
vice versa.

Additional header parameters MAY be present. The verification key for an
AAT or PoP JWT comes only from the configured trust anchors or from a
`cnf.jwk` in the chain: enforcement points MUST NOT use a key supplied
by a header parameter such as `jwk`, `jku`, `x5c`, or `x5u`; a token
carrying one is verified as if it were absent. Enforcement points MAY
use `kid` only to select among configured trust anchors. Enforcement
points MUST ignore other header parameters they do not recognize. If
`crit` is present, it MUST be processed per {{RFC7515}} Section 4.1.11:
an enforcement point that does not understand every parameter listed in
`crit` MUST reject the token.

The JWS Payload is the serialized claims object. An enforcement point
MUST verify the signature over the JWS Signing Input exactly as
presented and MUST NOT re-serialize or canonicalize the payload before
verification. Issuers and derivers SHOULD serialize AAT payloads as
JCS-canonical JSON {{RFC8785}} so that the signing input, and therefore
`par_hash` (Section 4.6), is reproducible across implementations; the
PoP JWT payload MUST be JCS-canonical (Section 7.2).

## Examples

### Root Token

Protected header:

~~~json
{"alg":"Ed25519","typ":"aat+jwt"}
~~~

Payload:

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

Protected header:

~~~json
{"alg":"Ed25519","typ":"aat+jwt"}
~~~

Payload:

~~~json
{
  "jti": "01957a41-0081-7c20-bf3a-00a0c91e1234",
  "iss": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK...",
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

# Attenuation Invariants

Every presented chain MUST satisfy the following invariants: I1
through I5 at each derivation step, and I6 for the presentation. The
verification algorithm in Section 8 enforces these invariants;
enforcement points MUST reject any chain that violates any invariant.

## Capability Lattice Model (Non-Normative)

This subsection gives an informal model, a capability lattice, for
reading the normative invariants that follow.

For a token `T`, define its capability set `C(T)` as the set of `(tool,
args)` pairs that `T` authorizes (that is, the pairs for which `T` would
permit invocation). The core security property of this protocol is:

~~~
C(child) ⊆ C(parent)
~~~

Every delegation step moves down or stays at the same position in this
partial order. A derived token can only authorize a subset of what its
parent authorized. It cannot add tools, loosen argument constraints, or
extend the chain's authority in any dimension this specification
defines (Sections 3.3 and 4).

Argument spaces are typically infinite, so Section 4.5 defines `⊆`
structurally, and those rules alone decide validity. They are
conservative: some attenuations that are valid in the semantic sense
below, such as an `exact` under a parent `any`, are rejected.

When a parent constraint exists, a parent constraint `c_parent` subsumes
a derived constraint `c_child` (written `c_child ⊑ c_parent`) if every
argument value that satisfies `c_child` also satisfies `c_parent`. A
derived constraint attenuates its parent exactly when the parent
subsumes it.

Two boundary cases complete the structure. The empty capability set
`∅` is the bottom element: a token with no tools authorized is a
valid token that cannot authorize tool invocations. If it is not the
leaf, it can only derive further empty-capability tokens. The root
token's capability set is the ceiling for the entire chain: no derived
token at any depth can exceed what the root authorized.

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
holder to derived token issuer. This invariant establishes a
cryptographic holder-key trail: each link in the chain was signed by the
party that held the preceding token. Attributing that key to a human,
service, organization, or control plane is a deployment responsibility.

## I2: Depth Monotonicity

~~~
derived.del_depth == parent.del_depth + 1
derived.del_depth <= parent.del_max_depth
derived.del_depth <= derived.del_max_depth
derived.del_depth <= MAX_DELEGATION_DEPTH
derived.del_max_depth <= parent.del_max_depth
~~~

Delegation depth increments exactly by one at each link. A presented
chain is a single linear path: it cannot skip depths or contain the same
token instance more than once. Broader delegation activity may form a
graph across multiple derived tokens and chains, but each invocation is
verified against one ordered root-to-leaf path. `del_max_depth` is an
absolute ceiling, not a remaining count. A token is terminal (its holder
cannot derive further tokens) when `del_depth == del_max_depth`. A root
token with `del_max_depth: 0` is therefore immediately terminal and
cannot produce any derived tokens.

The `del_max_depth` claim is an issuer-imposed bound on chain growth. It
limits resource exhaustion and bounds the number of offline trust
extensions that can occur under one root grant. Issuers use this value
to express the maximum delegation depth they are willing to authorize
for the grant. Intermediate token holders can only lower
`del_max_depth`, never raise it (I2), so the root issuer's depth bound
is enforced by chain verification across the entire chain.

Issuers SHOULD set `del_max_depth` to accommodate the expected
delegation topology (Appendix B.4). Once a chain reaches it, no
descendant can extend it; more depth requires a new root grant.

MAX_DELEGATION_DEPTH is an implementation-defined finite integer
specifying the maximum permitted delegation chain depth. Implementations
MUST enforce a finite maximum delegation depth to prevent resource
exhaustion, and SHOULD size it to their deployment topology (Appendix
B.4). So that chains verify across implementations, MAX_DELEGATION_DEPTH
MUST be at least 8.

The `del_max_depth` claim in any token in the chain MUST NOT exceed the
implementation's MAX_DELEGATION_DEPTH.

### Implementation Resource Limits

MAX_TOKEN_SIZE is an implementation-defined finite integer specifying
the maximum encoded size of a single token in bytes. Implementations
MUST enforce this limit to prevent memory exhaustion from pathologically
large tokens. A value of 65536 bytes (64 KiB) is RECOMMENDED.

MAX_CHAIN_SIZE is an implementation-defined finite integer specifying
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
Appendix B.7).

A derived token cannot outlive its parent. Authority cannot extend
beyond the lifetime of the token that granted it. A derived token's
issuance time MUST NOT precede its parent's issuance time; a deriver
whose clock lags the parent's issuer sets `iat` to `parent.iat`
(Section 6.2, step 2). Tokens
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
authorize. For each tool that appears in both parent and derived token,
with both constraint maps normalized so that an empty map is
`{"*": {"constraint_type": "wildcard"}}` (Section 3.3):

- Each argument key the derived map names MUST also be named by the
  parent's map, unless the parent's map contains `"*"`. A key named only
  under the parent's `"*"` is an argument the parent already permitted
  with any value, so constraining it narrows.
- An argument the parent requires MUST remain required in the derived
  map. Making an optional argument required narrows; the reverse would
  admit invocations that omit an argument the parent requires.
- The derived map MAY omit a key the parent names only if the parent
  marks it optional and the derived map does not contain `"*"`. The
  omitted argument then becomes forbidden, which narrows; if the parent
  requires it, every derived invocation would lack it.
- The derived map MAY contain `"*"` only if the parent's map does.
  Dropping `"*"` narrows; adding it would admit arguments the parent
  forbids.

For each argument key named in both maps, the derived constraint MUST be
at least as restrictive as the parent's constraint.

These rules do not let a derived token forbid one argument while keeping
`"*"`: the argument would return under `"*"`. A deriver that needs this
drops `"*"` and names the arguments it keeps.

Constraint subsumption is defined per constraint type. The following
table lists every valid (parent, derived) pair of core types; each row
is a parent type, and each entry a derived type that the parent
subsumes, under the stated condition. Every other pair is invalid and
MUST be rejected, unless a registered extension constraint type
declares it (Section 5.1).

| Parent | Valid derived constraints |
|---|---|
| `exact` | `exact` with the same value |
| `range` | `range` at least as tight (below); `exact` whose value is a number the parent range accepts |
| `one_of` | `one_of` whose values are a non-empty subset of the parent's; `exact` whose value is a member of the parent's values |
| `not_one_of` | `not_one_of` whose excluded values are a superset of the parent's |
| `contains` | `contains` whose required elements are a superset of the parent's |
| `subset` | `subset` whose allowed elements are a subset of the parent's |
| `all` | `all` in which every parent clause subsumes at least one derived clause (below) |
| `any` | `any` in which every derived clause is subsumed by at least one parent clause (below) |
| `wildcard` | any constraint |

A derived `one_of` cannot be empty; to authorize no value, the deriver
omits the tool. A derived `not_one_of` under a parent `one_of` is
invalid: it accepts values outside the parent's set, and the parent
cannot be verified to subsume it without domain knowledge.

The rules for `range`, `all`, and `any` need more detail:

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

- **all:** A derived `all` constraint attenuates a parent `all`
  if every parent clause subsumes at least one derived clause.
  Formally: for each `clause_p` in `parent.all.constraints`, there
  MUST exist a `clause_d` in
  `derived.all.constraints` such that `clause_d ⊑ clause_p` per this
  section. A single derived clause MAY satisfy more than one parent
  clause. The derived constraint MAY add additional clauses, which
  only further restrict the accepted value set. If any parent clause
  subsumes no derived clause, the check MUST fail. An `all`
  constraint whose `constraints` array is empty is invalid in both
  the parent and the derived position and MUST be rejected; an empty
  conjunction would accept every value while appearing to constrain
  it.

  This matching rule is sound: if `C_d ⊑ C_p1` and `C_d ⊑ C_p2`, then
  `C_d.check(v)` implies both `C_p1.check(v)` and `C_p2.check(v)`, so
  `C_d` is a valid attenuation of `all([C_p1, C_p2])`. Requiring a
  one-to-one assignment of derived clauses to parent clauses adds
  backtracking without adding soundness, and rejects valid
  attenuations such as `all([wildcard, wildcard])` to
  `all([exact(5)])`.

  ~~~
  function check_all_subsumption(parent_clauses, derived_clauses):
    for C_p in parent_clauses:
      if not any(subsumes(C_p, C_d) for C_d in derived_clauses):
        return FAIL
    return PASS
  ~~~

- **any:** A derived `any` constraint attenuates a parent `any`
  constraint if every clause in the derived constraint is
  subsumed by at least one clause in the parent constraint,
  using the per-type subsumption rules defined in this section.
  Formally: for each `clause_d` in
  `derived.any.constraints`, there MUST exist a `clause_p` in
  `parent.any.constraints` such that `clause_d ⊑ clause_p`.
  Removing clauses is valid (it narrows the accepted set).
  Adding clauses is invalid (it widens it). An `any` constraint
  whose `constraints` array is empty is invalid in both the parent
  and the derived position and MUST be rejected. Cross-type subsumption
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

## I5: Cryptographic Linkage

~~~
derived.par_hash ==
  base64url-nopad(SHA-256(parent token signing input))
~~~

Token signatures and `par_hash` serve distinct security roles. Signature
verification authenticates each token under the verification key
selected for that token: a trust anchor for a root token, or the parent
token's `cnf.jwk` for a derived token. Delegation authority (I1) then
checks that the child issuer corresponds to the parent holder key.
However, these checks do not by themselves bind the child to a unique
parent token instance when the same holder key has multiple compatible
parent tokens. The `par_hash` claim provides that token-instance binding
by committing the child to exactly one parent token's signing input.

Each derived token is cryptographically bound to its parent by including
the SHA-256 digest of the parent token's signing input in the
`par_hash` claim. For JWT/JWS AATs, the parent token signing input is
the JWS Signing Input: the ASCII string
`BASE64URL(JWS Protected Header) || '.' || BASE64URL(JWS Payload)` as
defined in {{RFC7515}} Section 5.1.

This binding prevents grant-context substitution: pairing a child with
a different parent held by the same key, which would discard
restrictions only the real parent carries (Section 9.1.1).

## I6: Proof of Possession

~~~
pop_signature verifies under leaf.cnf.jwk
~~~

The presenter of a token chain MUST demonstrate control of the private
key corresponding to the leaf token's `cnf.jwk`. Proof of Possession is
defined in Section 7.


# Extension Constraint Registry

Implementations MAY support extension constraint types beyond those
listed in Section 3.4. Every extension constraint type MUST be
registered in the IANA AAT Constraint Type Registry (Section 11.3),
whose expert review checks that its subsumption procedure is sound. An
implementation that evaluates an unregistered constraint type does not
conform to this specification for chains that contain it. The registry
does not require all implementations to support every registered
extension.

## Attenuation Compliance Requirement

The capability monotonicity invariant (I4, Section 4.5) applies to
extension constraint types without exception. An extension constraint
type MUST NOT be registered unless its registration defines all of the
following.

**A subsumption verification procedure.** The registration MUST provide
a complete, formal definition of what it means for one instance of the
constraint to be at least as restrictive as another instance of the same
constraint type. This procedure MUST satisfy three properties:

1. **Decidable.** The procedure MUST terminate in time polynomial
   in the size of its inputs. If deciding containment for the
   type's constraint language is more expensive than that, the
   registration MUST prescribe a conservative syntactic strategy
   that meets this bound and MUST formally justify that the
   strategy is sound (never accepts a non-subsuming pair). The
   registration MUST state the worst-case cost of both the
   procedure and the type's `check` predicate (Section 9.6).

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

A registration MUST NOT define a member named `optional`, which Section
3.3 reserves.

**Cross-type subsumption rules.** The registration MUST list every
(parent type, child type) pair involving the new type and a core type
defined in Section 3.4 or a previously registered extension type that
is a valid attenuation, with its conditions. Enforcement points MUST
treat unlisted pairs as invalid. A parent `wildcard` subsumes every
type, including extension types, and need not be listed.

## Enforcement Point Obligations

When an enforcement point encounters an extension constraint type during
chain verification, it MUST:

1. Apply the type's subsumption procedure and `check` predicate as
   defined by its registration. An enforcement point that does not
   implement the type MUST reject the chain (fail-closed).

2. Evaluate the subsumption relation at every chain link where
   the constraint appears, as part of the I4 check. A chain link
   where the parent constraint does not subsume the derived
   constraint MUST be rejected.

3. Evaluate the constraint's `check` predicate against the
   presented argument value during authorization. If the predicate
   returns false, the invocation MUST be denied.

## Example Registration: Path Containment

The following is an illustrative example of a conforming extension
constraint registration. It is not defined normatively in this document.

**Type name:** `path_containment`

**Additional members:** `root` (string, required). An absolute path root.

**`check` predicate:** The argument, after resolving all `.` and `..`
components and removing redundant separators, must be equal to `root` or
lie beneath `root` after path-segment normalization. The normalization
step is part of the predicate; implementations that compare raw argument
strings without normalization do not conform to this registration.

**`subsumes` relation:** `subsumes(C_parent, C_child)` is true if and
only if `C_child.root` is `C_parent.root` or lies beneath
`C_parent.root` under the normalized path-segment ordering.

**Cross-type subsumption:** A parent `path_containment` constraint
subsumes a derived `exact` constraint if and only if the exact value,
after normalization, is equal to the parent's `root` or lies beneath it.
All other cross-type pairs involving `path_containment` are invalid.

# Issuance and Derivation

## Root Issuer Support and Root Token Issuance

The token endpoint is used only for root AAT issuance. Derived tokens
are created locally by token holders as described in Section 6.2 and do
not require token endpoint interaction. Enforcement points verify
presented chains offline as described in Section 8.

### Root Issuer Discovery

A root issuer that supports AAT issuance SHOULD advertise this
capability using the following metadata parameter in its
authorization server metadata document {{RFC8414}}, if supported.

| Metadata Parameter | Value |
|---|---|
| `aat_issuer` | Boolean. `true` if the AS can issue AAT root tokens. |

This document requests registration of `aat_issuer` in the IANA OAuth
Authorization Server Metadata registry (Section 11.4).

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

The key submitted in `req_cnf` is the AAT holder key that will be
embedded in the root token's `cnf.jwk`. This key is distinct from any
credential the client uses to authenticate to the token endpoint. Client
authentication establishes which OAuth client is requesting issuance;
`req_cnf` establishes which key will hold the issued AAT and derive or
present downstream tokens. Deployments MAY require these credentials to
be controlled by the same workload or agent.

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
6. For each tool identifier in the requested `authorization_details`,
   verifies that the tool is recognized by the root issuer and that the
   requester is authorized to receive authority for it. The mechanism
   for mapping requester identity to tool authority is
   deployment-specific and outside the scope of this specification.
7. Sets `authorization_details` to the capability claims granted. The
   granted claims MUST attenuate the requested claims under the rules
   of Section 4.5, treating the request as the parent, and MUST NOT
   include a tool that failed verification in step 6. If no requested
   tool can be granted, the root issuer MUST reject the request with
   the `invalid_authorization_details` error ({{RFC9396}} Section 5).
8. Signs the token with the AS's own private key.

The AS returns the token in a standard OAuth 2.0 token endpoint response
({{RFC6749}} Section 5.1) with the following field values:

~~~
{
  "access_token": "<compact-serialized AAT JWT>",
  "token_type": "aat",
  "expires_in": <seconds until exp>,
  "authorization_details": [<the granted entries>]
}
~~~

As {{RFC9396}} Section 7 requires, the response carries the granted
`authorization_details`, which equal those in the token.

The `token_type` value `"aat"` is registered in Section 11.5. This
specification uses the token endpoint so that existing OAuth 2.0
deployments can issue root tokens; other issuance profiles are out of
scope. Clients MUST NOT treat the returned token as a bearer token: its
only valid use is as the root of an AAT delegation chain presented to
an enforcement point (Section 8). The AS does not store or track
derived tokens, which holders create without contacting it.


## Token Derivation

A holder of any AAT whose `del_depth` is strictly less than
`del_max_depth` MAY derive a child token as follows.

1. Set `jti` to a fresh unique token identifier, RECOMMENDED to
   be a UUIDv7 value per {{RFC9562}}.

2. Set `iat` to the current time, but not earlier than `parent.iat`.
   Set `exp` to any value <= `parent.exp`, subject to the
   constraints in Section 4.4 (see Appendix B.7 for guidance).

3. Select the set of tools to authorize. This set MUST be a
   subset of the tools authorized by the parent token.

4. For each tool, construct a constraint map whose keys satisfy
   the key rules of Section 4.5 relative to the parent's map, with
   each constraint at least as restrictive as the parent's
   corresponding constraint (or the parent's `"*"` constraint, for a
   key the parent does not name).

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
   appear in this field. When the child is delivered across a
   process or trust boundary, `cnf.jwk` MUST NOT be the parent's
   key: a recipient holding the parent's key could also present
   the parent's token (Section 9.1.1).

9. If the holder knows where the derived token will be presented,
   set `aud` to restrict it and its descendants to those
   enforcement points (Section 3.2). A parent's `aud` need not be
   copied; every `aud` in the chain is checked (Section 8, step 6c).

10. Sign the token with the private key corresponding to the
    parent token's `cnf.jwk`, using the JWS Protected Header
    defined in Section 3.5. The `iss` claim MUST be set to the
    JWK Thumbprint URI {{RFC9278}} of that signing key, using the
    SHA-256 hash algorithm.

Derivation is performed locally by the token holder. No authorization
server communication is required.

A derivation in which none of the authority dimensions is strictly
narrowed (the tool set is identical, all constraints are unchanged,
`del_max_depth` is unchanged, and `exp` is unchanged) is technically
valid by the invariants. Such a child has the same capability and
lifetime authority as its parent while consuming one delegation depth.
It does not improve least privilege, but deployments may use it for
holder-key handoff. Enforcement points MAY log same-scope derivations as
anomalous according to deployment policy.


# Proof of Possession

## Rationale

A token without proof of possession can be replayed by any party that
obtains a copy of the token. In agent systems, tokens flow through
model context, tool invocation results, and inter-agent message
channels, all of which are observable by other components. PoP
binds a specific invocation to the private key of the leaf
token's holder.

## PoP JWT Structure

The holder of the leaf token produces a PoP JWT for each tool
invocation. The PoP JWT is a compact serialization signed with the
holder's private key. It MUST contain the required claims listed below.

| Claim | Type | Required | Description |
|---|---|---|---|
| `jti` | string | REQUIRED | Fresh random identifier. The holder MUST NOT reuse a `jti` value across PoP JWTs it produces. When a UUID is used, it MUST be encoded as a lowercase hyphenated string per {{RFC9562}}. Whether an enforcement point can detect reuse depends on whether stateful `jti` tracking is deployed (see Section 9.5). |
| `iat` | NumericDate | REQUIRED | Time of PoP creation. MUST reflect the actual time of creation. Enforcement points validate this against a clock tolerance window (Section 9.10). |
| `aat_id` | string | REQUIRED | The `jti` of the leaf token being presented. |
| `aat_hash` | string | REQUIRED | Base64url-encoded SHA-256 digest of the leaf token's signing input, computed as for `par_hash` (Section 4.6). Binds the proof to the exact leaf token presented, following the DPoP `ath` claim ({{RFC9449}} Section 4.2). |
| `aat_tool` | string | REQUIRED | The tool identifier being invoked. MUST exactly match a key in the `tools` map of the leaf token's `authorization_details`. Tool identifier matching follows the exact-string comparison rules in Section 3.3.1. |
| `aat_aud` | string | OPTIONAL | Presentation audience: identifies the party to which the holder presents this PoP JWT, with the semantics of the JWT `aud` claim ({{RFC7519}} Section 4.1.3) and the target binding of DPoP `htu` ({{RFC9449}}). It names the next hop, never a resource behind it that the holder cannot see (Section 9.5). When present, an enforcement point MUST reject a PoP JWT whose `aat_aud` does not identify itself. An enforcement point MAY require the claim. |
| `nonce` | string | OPTIONAL | A value previously supplied by this enforcement point, following the server-provided nonce pattern of DPoP ({{RFC9449}} Section 9). An enforcement point that requires a nonce MUST reject a PoP JWT that omits it or carries a value the enforcement point did not issue or no longer accepts. How the nonce reaches the holder is transport-specific and out of scope. The claim name is the registered `nonce` claim ({{OIDC.Core}}, as updated by {{RFC9449}} Section 12.7.1). |
| `hta` | object | REQUIRED | The tool arguments for this invocation. Keys are argument names; values are argument values. |

The PoP JWT payload MUST be serialized as JCS-canonical JSON
({{RFC8785}}) before JWS signing. This is a whole-payload requirement,
not specific to the `hta` member. The JWS signing input is therefore
`BASE64URL(JWS Protected Header) || '.' || BASE64URL(JCS(PoP claims))`.
Whole-payload JCS canonicalization ensures a deterministic byte
representation; in particular, it gives `hta` stable equality semantics
so that argument map comparison is unambiguous across implementations
and languages regardless of JSON serialization choices, such as key
order or `1.0` versus `1`.

The PoP JWT MUST be signed using the private key corresponding to the
leaf token's `cnf.jwk`. The enforcement point verifies the PoP JWT
signature against the leaf token's `cnf.jwk`.

Protected header:

~~~json
{"alg":"Ed25519","typ":"aat-pop+jwt"}
~~~

Payload:

~~~json
{
  "jti": "c980f2a1-4a37-4e88-bb3c-9defd37c1a45",
  "iat": 1741600300,
  "aat_id": "01957a41-0081-7c20-bf3a-00a0c91e1234",
  "aat_hash": "sha256_base64url_of_leaf_token_signing_input",
  "aat_tool": "read_file",
  "aat_aud": "https://tools.example.com",
  "hta": { "path": "/data/q3-report.pdf" }
}
~~~

## Verification

PoP verification is only meaningful against a leaf token whose chain has
been fully verified per Section 8. An enforcement point MUST complete
chain verification (Section 8, steps 1-5) before evaluating the PoP JWT.
A valid PoP JWT against an unverified or invalid chain MUST NOT result
in authorization.

The enforcement point verifies the PoP JWT as specified in Section 8,
step 7; any failed check denies the invocation.

The `iat` check is stateless and bounds replay to the tolerance window:
a captured PoP JWT remains usable until its `iat` leaves the window. It
MUST NOT be the only replay control for tool invocations that have side
effects or are not idempotent. For those, the enforcement point MUST
track presented `jti` values, retaining each one only until its `iat`
leaves the window (Section 8, step 7i). The enforcement point
determines which of its tools have side effects; tokens do not carry
this. Replicas of one enforcement point, such as instances behind a
load balancer, share `jti` state.

Accepting a PoP JWT at most once across a deployment additionally
requires that no other enforcement point accept the same proof: either
by sharing `jti` state or by binding the proof to one enforcement point
through chain audience, `aat_aud`, or a nonce (Section 9.5).

## Presentation

A presentation is what a holder sends to an enforcement point for one
tool invocation: the delegation chain and the PoP JWT for that
invocation. This specification defines what a presentation contains, not
how it is carried; a binding to a particular protocol defines where the
presentation travels and how the enforcement point obtains the
invocation's tool identifier and arguments (Section 1).

When a binding carries a presentation as JSON, it uses an object with
these members:

| Member | Type | Description |
|---|---|---|
| `aat_chain` | array of strings | The chain in root-to-leaf order, each token in JWS Compact Serialization. |
| `aat_pop` | string | The PoP JWT in JWS Compact Serialization. |

~~~json
{
  "aat_chain": [
    "eyJhbGciOiJFZDI1NTE5Ii...",
    "eyJhbGciOiJFZDI1NTE5Ii..."
  ],
  "aat_pop": "eyJhbGciOiJFZDI1NTE5Ii..."
}
~~~

The two members are the `chain` and `pop_jwt` inputs of the Section 8
algorithm. A binding MUST preserve the order of the chain and MUST NOT
separate a PoP JWT from the chain it was produced for. Enforcement
points ignore members they do not recognize. A chain of several tokens
can exceed the header size limits of common HTTP intermediaries
(Appendix B.5), so bindings SHOULD carry the presentation in a message
body or in protocol metadata rather than in an HTTP header field.


# Chain Verification Algorithm

The enforcement point receives a chain of tokens ordered from root to
leaf and MUST execute the following algorithm. Any failure MUST result
in denial.

Verification requires only the token chain and the configured trust
anchors; no network calls or authorization server availability are
required. An enforcement point that tracks PoP `jti` values (Section
7.3) or issues nonces (step 7h) keeps that state locally, outside the
inputs of this algorithm.

~~~
Inputs:
  chain:         ordered array of signed JWTs, [root, ..., leaf]
                 (aat_chain in a presentation, Section 7.4)
  trust_anchors: set of (issuer, public key) pairs trusted as
                 root issuers
  tool:          the tool being invoked
  args:          the arguments being passed to the tool
  pop_jwt:       the PoP JWT for this invocation
                 (aat_pop in a presentation, Section 7.4)

Algorithm:

1. If chain is empty, DENY.

2. Verify chain size limits:
   a. Verify the encoded size of each token does not exceed
      MAX_TOKEN_SIZE. If any token exceeds this limit, DENY.
   b. Verify the total encoded size of the chain does not exceed
      MAX_CHAIN_SIZE. If the chain exceeds this limit, DENY.
   c. For each token, decode the base64url payload segment and
      extract only the `jti` field using minimal JSON parsing.
      If a string-valued `jti` field cannot be extracted, DENY.
      Collect all extracted `jti` values; if any value appears
      more than once in the presented chain, DENY (token-instance
      cycle detection). The extracted `jti` values MUST be treated
      as untrusted until each token's signature is verified.

3. Verify root token:
   a. Verify the root token's JWS alg header is on the
      implementation's permitted algorithm allowlist and is
      consistent with the verifying trust anchor key's kty and
      crv parameters. Verify the JWS typ header equals
      "aat+jwt". If alg is "none", not on the allowlist,
      inconsistent with the key type, or typ is absent or not
      "aat+jwt", DENY. If a crit header lists a parameter this
      enforcement point does not understand, DENY.   (Sec 3.5)
   b. Verify the root token signature against the public key
      of a trust anchor. After signature verification succeeds,
      parse the root token's claims, rejecting any JSON object
      with duplicate member names, and verify root.iat and
      root.exp are present and are NumericDate values (Section
      3.2). If not, DENY. All subsequent root checks (3c through
      3n) operate on parsed claims.
   c. Verify root.del_depth is an integer (Section 3.2) equal to
      0.
   d. Verify root.par_hash is absent.
   e. Verify root.exp > now.
   f. Verify root.iat <= now + MAX_IAT_SKEW.
   g. Verify root.exp > root.iat.
   h. Verify root.exp <= root.iat + MAX_TOKEN_LIFETIME.
   i. Verify root.del_max_depth is a non-negative integer not
      exceeding MAX_DELEGATION_DEPTH. If absent or invalid, DENY.
   j. Verify root.jti is present and is a non-empty string.
      If absent or not a string, DENY.
   k. Verify root.iss is present, is a URI, and equals the
      issuer of the trust anchor whose key verified the
      signature in step 3b (RFC 8725, Section 3.8). If
      absent, not a URI-formatted string, or not equal, DENY.
   l. Verify root.cnf is present, contains a `jwk` member, and
      that the `jwk` encodes a public key (MUST NOT contain a
      private key parameter such as `d` for EC/OKP keys or
      `p`, `q` for RSA keys). If absent or invalid, DENY.
   m. Verify root.authorization_details is present and is a
      non-empty array containing exactly one entry with type
      "attenuating_agent_token", and that the entry's `tools`
      member is present and is a JSON object whose values are
      JSON objects. If not, DENY.
   n. For each constraint in each constraint map in the root
      token's attenuating_agent_token entry, verify the
      constraint tree depth does not exceed MAX_CONSTRAINT_DEPTH,
      that every constraint in it is of a type this enforcement
      point implements (Sections 3.4 and 5.2) and is well-formed
      (Section 3.4), and that no `all` or `any` constraint has an
      empty `constraints` array. If any check fails, DENY.

4. For each adjacent pair (parent, child) in chain:
   a. Verify child token's JWS alg header is on the
      implementation's permitted algorithm allowlist and is
      consistent with parent.cnf.jwk's kty and crv parameters.
      Verify the JWS typ header equals "aat+jwt". If alg is
      "none", not on the allowlist, inconsistent with the key
      type, or typ is absent or not "aat+jwt", DENY. If a crit
      header lists a parameter this enforcement point does not
      understand, DENY.                              (Sec 3.5)
   b. Verify child signature under the key in parent.cnf.jwk. (I1)
      After signature verification succeeds, parse the child
      token's claims, rejecting any JSON object with duplicate
      member names, and verify required claims are present:
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
      b5. Verify child.iss and child.par_hash are present and are
          strings, and child.iat and child.exp are present and are
          NumericDate values (Section 3.2). If not, DENY.
   c. Verify child.iss equals jwk_thumbprint_uri(parent.cnf.jwk). (I1)
   d. Verify child.del_depth == parent.del_depth + 1.    (I2)
   e. Verify child.del_depth <= parent.del_max_depth.    (I2)
   f. Verify child.del_depth <= MAX_DELEGATION_DEPTH.    (I2)
   g. Verify child.del_max_depth <= parent.del_max_depth.(I2)
   h. Verify child.exp <= parent.exp.                    (I3)
   i. Verify child.exp > now.                            (I3)
   j. Verify child.iat >= parent.iat.                    (I3)
   k. Verify child.iat <= now + MAX_IAT_SKEW.            (I3)
   l. Verify child.exp > child.iat.                      (I3)
   m. Verify child.del_depth <= child.del_max_depth.     (I2)
   n. Verify child.authorization_details contains at most
      one entry with type "attenuating_agent_token", and that
      such an entry's `tools` member is present and is a JSON
      object whose values are JSON objects. If not, DENY. For the
      remaining checks in this
      step, define child_aat and parent_aat as the child's and
      the parent's "attenuating_agent_token" entry, or, where a
      token has none, an entry with an empty `tools` object (the
      empty capability set). Entries of other types are ignored.
   o. For each constraint in each constraint map in child_aat.tools,
      verify the constraint tree depth does not exceed
      MAX_CONSTRAINT_DEPTH, that every constraint in it is of a
      type this enforcement point implements (Sections 3.4 and 5.2)
      and is well-formed (Section 3.4),
      and that no `all` or `any` constraint has an empty
      `constraints` array. If any check fails, DENY.
   p. Verify capability monotonicity (Section 4.5):   (I4)
      p1. Verify every tool in child_aat.tools
          is also present in parent_aat.tools.
          If any child tool is absent from the parent, DENY.
      p2. For each tool present in both parent_aat.tools and
          child_aat.tools, normalize both constraint maps (Section
          3.3) and verify the key rules of Section 4.5: every key
          the child names is named by the parent unless the parent
          contains `"*"`; every key the parent names and the child
          omits is optional in the parent, and the child then does
          not contain `"*"`; and the child contains `"*"` only if the
          parent does. If any rule fails, DENY.
      p3. For each argument key named in both maps, verify that
          the child's constraint is required if the parent's is.
          If not, DENY.
      p4. For each argument key named in the child's map, verify
          that the parent's constraint for that key, or the
          parent's `"*"` constraint if the parent does not name it,
          subsumes the child's per the per-type rules in Section
          4.5, ignoring `optional`. If any child constraint does
          not attenuate its parent constraint, DENY.
   q. Verify child.par_hash equals base64url-nopad(      (I5)
      SHA-256(parent token signing input)), where
      base64url-nopad denotes base64url encoding without
      padding as described in JWS Appendix C. For JWT/JWS AATs,
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
   b. Verify tool is present in leaf_aat.tools, and that every
      number in args, as written in the invocation, is admissible
      (Section 3.4). Let M be the tool's constraint map,
      normalized (Section 3.3). For each argument in args: if M
      names it, verify its value satisfies that constraint;
      otherwise, if M contains `"*"`, verify the value satisfies
      M's `"*"` constraint; otherwise DENY (closed-world mode). For
      each argument M names that is required, if it is absent from
      args, DENY. If any constraint check fails, DENY.
   c. For each token in chain that carries an `aud` claim, verify
      that at least one of its values identifies this enforcement
      point (RFC 7519 Section 4.1.3). If any such token does not,
      DENY. If this enforcement point requires chain audience
      restriction (Sec 9.5) and no token in chain carries `aud`,
      DENY.

7. Verify PoP JWT:
   a. Verify the PoP JWT's JWS alg header is on the
      implementation's permitted algorithm allowlist and is
      consistent with leaf.cnf.jwk's kty and crv parameters.
      Verify the JWS typ header equals "aat-pop+jwt". If alg
      is "none", not on the allowlist, inconsistent with the
      key type, or typ is absent or not "aat-pop+jwt", DENY.
      If a crit header lists a parameter this enforcement point
      does not understand, DENY.                     (Sec 3.5)
   b. Verify pop_jwt signature under leaf.cnf.jwk. After
      signature verification succeeds, parse the PoP JWT claims,
      rejecting any JSON object with duplicate member names. (I6)
   c. Verify pop_jwt.jti, pop_jwt.aat_id, pop_jwt.aat_hash, and
      pop_jwt.aat_tool are present and are non-empty strings,
      pop_jwt.iat is a NumericDate value (Section 3.2), and
      pop_jwt.hta is
      present and is a JSON object; then verify pop_jwt.aat_id ==
      leaf.jti and pop_jwt.aat_hash equals
      base64url-nopad(SHA-256(leaf token signing input)). If not,
      DENY.
   d. If pop_jwt.aat_aud is present, verify it identifies this
      enforcement point. If it does not, DENY. If it is absent
      and this enforcement point requires PoP audience binding
      (Sec 9.5), DENY.
   e. Verify pop_jwt.aat_tool equals tool using the exact-string
      matching rules in Section 3.3.1.
   f. Verify pop_jwt.hta, when JCS-canonicalized, equals the
      JCS-canonical form of the args map for this invocation. If the
      canonical byte sequences differ, DENY.
   g. Verify pop_jwt.iat is within the clock tolerance
      window (Section 9.10). If outside the window, DENY.
   h. If this enforcement point requires a nonce (Sec 9.5),
      verify pop_jwt.nonce is present and is a value this
      enforcement point issued and still accepts. If absent,
      unknown, or expired, DENY.
   i. If this enforcement point tracks PoP `jti` values for the
      invoked tool (Section 7.3), verify pop_jwt.jti has not been
      accepted within the tolerance window. If it has, DENY. The
      jti is recorded as accepted only when step 8 permits the
      invocation, so a denied invocation consumes no jti.

8. PERMIT.
~~~

Notes on the algorithm:

- For a single-token chain (root = leaf), step 4 does not run; steps 3,
  5, 6, and 7 carry the checks, and steps 3b, 3c, and 3i-3m ensure
  required claims are present before later steps use them.
- Two requirements hold by induction and need no step of their own:
  every `del_max_depth` is at most MAX_DELEGATION_DEPTH (steps 3i and
  4g), and every `exp` is at most its token's `iat` plus
  MAX_TOKEN_LIFETIME (steps 3h, 4h, and 4j). Implementations MAY check
  them explicitly.
- A non-leaf token with no "attenuating_agent_token" entry is the empty
  capability set; step 4p accepts it as an attenuation, and step 6a
  rejects it as a leaf. A root always has an entry (step 3m).
- Two requirements bind producers only and have no step: the JCS form
  of the PoP payload (Section 7.2), which step 7f does not rely on
  because it canonicalizes `hta` itself, and the lowercase form of
  UUID `jti` values (Section 3.2).
- Step 2c detects a token instance presented twice. The same holder key
  or actor may still appear more than once, through distinct tokens.

Every step denies on failure, so the verdict does not depend on the
order of steps 6 and 7. Enforcement points SHOULD verify the PoP
signature (steps 7a and 7b) before evaluating argument constraints
(step 6b), so that a presenter who does not hold the leaf key cannot
trigger constraint evaluation.

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
verified. Steps 3b, 4b, and 7b reject duplicate JSON member names when
claims are parsed, because parsers differ in which duplicate they keep
({{RFC8259}}, Section 4).


# Security Considerations

## Threat Model

This section characterizes the threats that AATs mitigate and the
threats that are outside the scope of this mechanism. Deployments can
use this characterization to identify the complementary controls their
threat environment requires.

### Threats Mitigated

**Prompt injection leading to unauthorized tool invocation.** An
attacker who injects instructions into an agent's input cannot cause the
agent to invoke tools outside the scope encoded in its token. The
enforcement point rejects any invocation of an unauthorized tool
regardless of the agent's stated rationale. This holds only while the
holder private key is out of the model's reach: an agent that can read
or exfiltrate its key can act with the full scope of every token bound
to it.

**Hallucinated tool invocations with out-of-scope arguments.** Even
when an agent invokes an authorized tool, argument constraints in the
leaf token restrict the argument values the enforcement point will
accept. An agent that hallucinates an argument value outside the
authorized range is denied at the enforcement point before the tool
executes.

**Confused deputy attacks.** In agentic systems, the designation a
confused deputy acts on (Section 1) can come from an invoking principal,
prompt injection, tool output, or model error. AATs avoid relying on
standing authority: an agent acts under a token presented for the
current invocation. When the invoker derives that token to designate the
task's resource, designation and authority travel together, and the
agent cannot be steered outside the authority carried by the token. A
token authorizing more than one resource can still be steered within its
scope, so the holder deriving a leaf token SHOULD scope it as narrowly
as the task permits. How a constraint value maps to the resource the
tool acts on is defined by the tool contract: the protocol authorizes
the presented invocation, and the tool remains responsible for resolving
it to the correct resource.

**Privilege escalation and compromised sub-agents.** Authority can only
narrow at each delegation step (I4). A compromised or misbehaving
sub-agent is bounded by the scope of the token it holds: it cannot
invoke tools outside that scope, and any token it derives with broader
scope fails chain verification.

**Replay of a parent or intermediate token.** Derivation is additive:
a parent token remains valid after a child is derived from it, and an
orchestrator commonly derives several narrower tokens while retaining
its own. Every AAT in a chain, not only the leaf, carries a `cnf.jwk`
holder key, and an invocation is authorized only when the presenter
proves possession of the leaf token's key (I6, Section 7). A
sub-agent that obtains the bytes of its parent's token, or of the
root token, therefore cannot invoke with that token's authority and
cannot present it as the leaf of a chain: doing either requires the
parent holder's private key, which the protocol assumes is never
shared across a delegation boundary (Section 9.4).

**Grant-context substitution.** The `par_hash` claim (I5) binds each
derived token to the specific bytes of its parent token. Suppose a
delegator key holds two parent tokens, `A` and `B`, issued for different
tasks but authorizing compatible capabilities. The holder derives child
token `C` from `A`. Without `par_hash`, a presenter could assemble the
chain `(B, C)`. The link may satisfy delegation authority, depth,
lifetime, and capability monotonicity: `C` is signed by the key named in
`B.cnf.jwk`, has the expected depth, does not outlive `B`, and
authorizes no capability outside `B`. However, the chain has been
re-associated with task `B` rather than task `A`, and any restriction
only `A` carries, such as an `aud`, no longer applies. The `par_hash`
check rejects this because `C` commits to the signing input of `A`, not
`B`.

**PoP JWT replay.** For tool invocations with side effects, stateful
`jti` tracking at the enforcement point prevents PoP JWT replay
(Section 7.3); Section 9.5 covers replay across enforcement points.

### Threats Not Mitigated

**Malicious or compromised root issuer.** A root issuer that mints
tokens with overly broad scopes, or whose key is compromised,
undermines the authorization guarantees of every chain it anchors, and
AATs provide no mechanism to detect or constrain it. Root issuer
accountability is a deployment concern; key compromise and rotation are
discussed in Section 9.3.

**Compromised enforcement point.** An enforcement point that skips chain
verification, ignores constraint evaluation, or accepts forged tokens
provides no security guarantee regardless of the token format. AATs
assume enforcement points are honest and implement the verification
algorithm in Section 8 correctly. Enforcement point integrity is a
deployment concern.

**Actions within authorized argument constraints.** AATs restrict which
tools an agent may invoke and what argument values are permitted. They
do not restrict which authorized invocations an agent chooses to make,
in what order, or how many times. An agent that makes excessive or
unintended use of its authorized tools within the bounds of its token is
not detectable at the enforcement point. Rate limiting, audit logging,
and behavioral monitoring are complementary controls for this threat.
The constraint vocabulary cannot express them, because constraints apply
to argument values, not to sequences of invocations; a profile that
defines invocation-level controls needs its own attenuation rules and
enforcement state, as a profile defining approval gates would (Section
9.9).

**Compromised holder key.** Tokens bound to a stolen holder key are
usable at their full scope until they expire or are revoked; short
lifetimes bound the window (Section 9.4).

**Model exfiltration and side-channel attacks.** An attacker who
extracts an agent's model weights, system prompt, or in-context state
may be able to predict or manipulate the agent's behavior independently
of its token constraints. AATs operate at the authorization layer and
have no visibility into the model layer.

## Attenuation as the Security Invariant

The capability-containment guarantee of this specification rests on the
enforcement of the capability monotonicity invariant (I4). An
enforcement point that fails to check I4, or that checks it incorrectly,
provides no blast radius containment. Implementers should test I4
enforcement against every (parent type, child type) pair in Section 4.5,
including the pairs that enforcement points MUST reject.

The remaining invariants (I1-I3, I5, I6) rely on well-established
cryptographic primitives and validation patterns with substantial prior
art in deployed systems. I4 carries this specification's main
contribution: SPKI/SDSI (Section 1.3) established attenuation by
reduction, and this document defines typed subsumption rules over tool
arguments that make it checkable offline. Implementers are encouraged to
publish independent analyses of both the core subsumption rules and any
extension constraint types they deploy. Implementation and formal
verification status is described in Appendix F.

## Root Key Compromise

A compromised trust anchor key allows an attacker to issue arbitrary
root tokens. This breaks the security guarantees of all chains anchored
to that key.

In the base chain verification algorithm, configured trust anchors are
used to verify root tokens. Establishing, rotating, or revoking those
trust anchors is outside the scope of this specification. Remote
attestation mechanisms, such as the RATS architecture {{RFC9334}}, can
complement AAT deployments by providing evidence about root issuer or
enforcement point environments.

Deployments SHOULD implement key rotation and revocation procedures
appropriate to their risk model. Rotating a compromised trust anchor
means replacing its key and re-issuing root tokens; enforcement points
SHOULD support configurable trust-anchor sets so rotation needs no
downtime. Revocation list formats and distribution are outside the
scope of this specification.

## Holder Key Compromise

A compromised holder key allows an attacker to present existing tokens
issued to that holder, but not to derive broader ones. The response is
revoking tokens bound to that key where the deployment supports
revocation (Section 9.8), or letting short-lived tokens expire.

AATs do not provide the re-keying property of HMAC-chained designs
such as Macaroons {{MACAROONS}}, where adding a caveat replaces the
signing key so that the less-attenuated token can no longer be
produced from the more-attenuated one. In an AAT chain the parent
token continues to exist and remains valid until it expires or is
revoked, and its use is controlled by the parent holder's key rather
than by replacement of the signing key. Compromise of a holder key
therefore exposes every token bound to that key, at that token's full
scope, for the remainder of its lifetime. The design bounds this
exposure with holder binding on every chain position, attenuation at
every hop, and short lifetimes (Appendix B.7), rather than by making
parent tokens unrecoverable. Deployments that require a holder to be
unable to exercise a parent's authority after delegating SHOULD derive
the child to a fresh holder key (Section 9.11) and then destroy the
private key bound to the parent token. The parent token remains
cryptographically valid until its `exp`, but it can no longer be
presented or used to derive further tokens. A holder that destroys
that key also gives up deriving further children from the parent, so
this approximation of re-keying suits single-delegation hops.

Derivation times are asserted by the deriver: a stolen holder key can
be used to derive children with any `iat` at or after the parent's,
until the parent expires, so I3 bounds how long authority lasts but not
when a derivation happened.

The protocol assumes that holder private keys are not shared across
delegation boundaries. Key generation, storage, rotation, and recovery
are deployment concerns and are outside the semantics of chain
verification.

## Replay Attacks

The `iat` window alone is a probabilistic control: a captured PoP JWT
can be replayed for up to about twice the clock tolerance, roughly 60
seconds at the RECOMMENDED setting (Section 9.10). Section 7.3
therefore requires `jti` tracking for tool invocations that have side
effects or are not idempotent, such as financial transactions, data
deletion, writes to external systems, or anything that cannot be
undone. Replaying a read-only invocation returns its result to whoever
replays it, so enforcement points SHOULD also track `jti` values, or
require a nonce, for tools whose responses are sensitive.

PoP JWTs are scoped to the invocation data they contain. Without
further binding, a PoP JWT captured at one enforcement point may be
replayable at another enforcement point that accepts the same chain,
tool identifier, and argument map within the timestamp window. This
specification provides three bindings against that replay, each
borrowed from an existing mechanism, and requires deployments to use
at least one where the exposure exists:

- **Chain audience.** A holder that knows where a token will be
  presented sets `aud` when deriving it (Section 3.2), as with Macaroon
  caveats {{MACAROONS}} and resource indicators {{RFC8707}}. Every
  enforcement point checks every `aud` in the chain against itself
  (Section 8, step 6c), so holders further down the chain need not know
  the target.
- **Presentation audience.** `aat_aud` names the party the holder
  hands the PoP JWT to, like DPoP `htu` {{RFC9449}}: the next hop,
  never a resource behind it. The holder always
  knows its next hop, so it can set the claim whenever that hop is
  the enforcement point. It is OPTIONAL because when an intermediary
  forwards the presentation unchanged, the next hop is not the
  enforcement point, and the holder omits the claim (see below).
- **Enforcement-point nonce.** The enforcement point supplies a
  nonce and requires the PoP JWT to carry it, following the DPoP
  server-provided nonce pattern ({{RFC9449}} Section 9). A proof
  bound to one enforcement point's nonce cannot be replayed at
  another, and the holder never needs to name or know the
  enforcement point.

An intermediary, a party that relays a presentation without being its
target, MUST either present under its own AAT with its own PoP JWT, as
in token exchange {{RFC8693}}, or forward the presentation unchanged. A
forwarded presentation is accepted only if its `aat_aud` is absent or
identifies the receiving enforcement point (Section 8, step 7d). A
holder whose presentation may be forwarded therefore omits `aat_aud`,
and an enforcement point that requires `aat_aud` does not accept
forwarded presentations.

A deployment in which more than one enforcement point, resource
server, or tenant can accept the same chain MUST ensure that each of
them does at least one of the following: require chain audience,
require `aat_aud`, require a nonce, or share `jti` tracking state with
the others.

This specification does not define the storage backend, consistency
model, or distribution protocol for `jti` state; the required
consistency depends on the deployment topology. Deployments SHOULD
layer application-level idempotency mechanisms for high-value
operations.

## Constraint Evaluation

The core constraint types are intended to have predictable evaluation
cost. Extension constraint types can introduce parser complexity,
algorithmic cost, normalization requirements, or external policy-engine
dependencies, so each registration states its worst-case cost and any
resource limits implementations should enforce (Section 5.1).
Enforcement points SHOULD impose evaluation timeouts on any extension
constraint type whose `check` predicate is not O(n) in the length of the
argument value. A constraint type the enforcement point does not
recognize or implement fails closed (Sections 3.4 and 5.2).

## Depth Limit

Each delegation hop introduces an additional agent into the trust chain:
the enforcement point necessarily trusts not only that the leaf token
holder is honest, but that every intermediate holder made sound
attenuation decisions. A compromised or misdirected intermediate agent
can narrow constraints in ways that serve an attacker's goals while
remaining within the invariants. The depth limit bounds the number of
such trust extensions that a single root grant can produce. Enforcement
points MUST check both `del_max_depth`, which is the root issuer's
policy for the chain, and their own MAX_DELEGATION_DEPTH, which protects
the enforcement point (Section 8, steps 3i, 4e-4g, and 4m); enforcing
only one ignores the other.

## Token Revocation

Revocation of individual AATs, including derived tokens, is outside the
scope of this specification. The offline delegation model trades
per-token revocation granularity for verifiability without authorization
server availability. This tradeoff is inherent in the verification
model.

Deployments SHOULD use short token lifetimes to bound exposure after key
compromise, token theft, or scope misconfiguration. A short-lived leaf
token provides a bounded damage window even when no revocation mechanism
is deployed. Root tokens SHOULD be issued with the shortest lifetime
that covers the delegated task (Appendix B.7).

A companion document may define revocation enforced by the enforcement
point that accepts a chain, invalidating a token and its descendants,
but not unrelated tokens held by the same key, without requiring the
root issuer to track derived tokens.

## Approval Gates

Deployments may require signed approvals before accepting particular
tool invocations. Approvals are outside the base algorithm; a profile
that defines them should specify how approval requirements are encoded
and attenuated, what request data an approval signs, how freshness is
checked, and which approvers and thresholds are trusted.

## Clock Skew

This specification uses clock-based checks in two distinct contexts with
different semantics. MAX_IAT_SKEW (Section 4.4) is a one-sided
future-dating tolerance applied to token `iat` values: it prevents a
token issued slightly in the future from being rejected due to minor
clock drift between issuer and enforcement point. The PoP JWT timestamp
window (Section 8, step 7g) is a bilateral replay window applied to PoP
JWT `iat` values: it bounds how long a captured PoP JWT remains usable.
These are independent parameters enforced at different points in the
verification algorithm and SHOULD be configured separately.

PoP JWT timestamp verification requires synchronized clocks. The
RECOMMENDED window is ±30 seconds, which accommodates typical
NTP-synchronized deployments; deployments with well-synchronized clocks
can use ±5 to ±10 seconds, or less. Implementations MUST enforce a
finite window. Values beyond ±60 seconds add little clock-skew tolerance
while widening the replay window and are NOT RECOMMENDED; values near
±60 seconds suit only heterogeneous environments such as embedded
systems or degraded connectivity.

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
PoP proof; they do not infer agent runtime roles from token claims
unless a deployment-specific profile defines such claims and
verification rules.

## Algorithm Confusion

JWT/JWS AATs are signed JWTs. Implementations are subject to the full
class of JWT algorithm confusion attacks, including `alg: "none"`
acceptance, symmetric/asymmetric key confusion (RS256/HS256 key reuse),
and algorithm substitution across tokens in the same chain.

Enforcement points MUST maintain an explicit allowlist of permitted
signature algorithms and MUST reject any token whose `alg` header value
is not on that list. Implementations MUST NOT treat the absence of an
`alg` header as equivalent to any permitted algorithm. An `alg`
inconsistent with the verifying key's `kty` and `crv` is rejected even
when the signature would verify under another interpretation (Section
8, steps 3a, 4a, and 7a); for example, `"Ed25519"` requires an OKP key
with `"crv": "Ed25519"`.

Implementations MUST apply the algorithm allowlist independently to each
AAT in the chain and to the PoP JWT. Accepting a weaker algorithm on an
intermediate token because the leaf token used a strong algorithm is a
verification failure.

AATs and PoP JWTs MUST be signed with an asymmetric algorithm; `none`
and MAC algorithms MUST NOT be used ({{RFC9449}} Section 4.2). Any key
that can verify a MAC can also forge one. Ed25519 is mandatory to
implement (Section 3.2). ES256 is RECOMMENDED as the second algorithm,
and PS256 for root issuers with RSA keys. Algorithms are identified by
fully-specified values ({{RFC9864}}): Ed25519 is `"Ed25519"`, and the
deprecated polymorphic `"EdDSA"` MUST NOT be used.

## Optional and Unnamed Arguments

Optional and unnamed arguments trade enforcement for compatibility with
real tools, and each has a cost the enforcement point cannot see. When
an optional argument is omitted, the tool applies its own default: an
optional `head` on a file-reading tool lets a caller read the whole
file. Issuers SHOULD mark an argument optional only when the tool's
default for it is acceptable for the token's purpose. The `"*"` entry
admits any argument the tool accepts, including arguments that later
versions of the tool add, which a token issued earlier then authorizes
without anyone having reviewed them. Issuers SHOULD NOT use `"*"` for
tools with side effects, and enforcement points MAY reject arguments
absent from the tool's published input schema.

# Privacy Considerations

AAT payloads are integrity-protected but not encrypted. In cross-domain
deployments, an AAT chain can reveal delegation topology, task context,
tool identifiers, argument constraints, and holder-key correlation
information. Deployments SHOULD minimize disclosure of AAT chains to
parties that do not perform chain verification or invocation
authorization. Deployments SHOULD transmit AAT chains over encrypted
transport (e.g., TLS) and SHOULD protect stored tokens as sensitive
authorization metadata. A stored AAT is not usable without the
corresponding holder private key, but it can disclose authorization
scope and delegation structure. Token encryption is outside the scope of
this specification.

A PoP JWT's `hta` carries the invocation's argument values, which may
be personal data, to every enforcement point that verifies it.
Enforcement points SHOULD retain `jti` state and logged PoP JWTs no
longer than replay protection and audit require. A holder key reused
across tasks appears in each derived `iss` and links those tasks; fresh
holder keys per task prevent this.

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
semantics are governed by the AAT Constraint Type Registry (Section
11.3) and the RAR profile defined in this document, not by the JWT
Claims Registry.

**PoP JWT claims:**

| Claim Name | Claim Description | Change Controller | Reference |
|---|---|---|---|
| `aat_id` | AAT `jti` being presented | IETF | This document |
| `aat_hash` | Hash of the AAT being presented | IETF | This document |
| `aat_tool` | Tool identifier for PoP binding | IETF | This document |
| `aat_aud` | Presentation audience for PoP binding | IETF | This document |
| `hta` | Tool arguments for PoP binding | IETF | This document |

The `aud` claim on AATs (Section 3.2) and the `nonce` claim on PoP JWTs
(Section 7.2) are existing registered claims, from {{RFC7519}} and
{{OIDC.Core}} (as updated by {{RFC9449}}) respectively, and are not
re-registered.

## Authorization Details Type

{{RFC9396}} does not establish a registry of authorization details
types. This document uses the type `attenuating_agent_token`; whether to
create such a registry, with this type as an entry, or to use a
collision-resistant URI instead ({{RFC9396}} Section 2) is an open issue
for the working group.

## AAT Constraint Type Registry

This document requests IANA create the "Attenuating Authorization Token
Constraint Types" registry. The registration policy for this registry is
Specification Required {{RFC8126}}.

### Designated Expert Instructions

Designated experts MUST verify that a registration:

1. has a type name that is a lowercase string of letters, digits, and
   underscores and does not conflict with a registered name;
2. specifies its members and its `check` predicate precisely enough
   that independent implementations agree on every argument value;
3. meets the requirements of Section 5.1; and
4. has a stable, publicly accessible reference.

Designated experts SHOULD request clarification when cross-type rules
are incomplete, when soundness is not formally justified, or when the
`check` predicate leaves cases unresolved.

### Registration Template

~~~
Type name:
Additional members:   (name, JSON type, required or optional,
                       default, semantics)
check predicate:
subsumes procedure:   (Section 5.1, including whether it is
                       conservative and its soundness argument)
cross-type rules:     (Section 5.1)
cost:                 (Section 5.1)
security considerations:
reference:
~~~

### Initial Registry Entries

The initial entries are the core types `exact`, `range`, `one_of`,
`not_one_of`, `contains`, `subset`, `wildcard`, `all`, and `any`, each
with reference "This document (Sections 3.4 and 4.5)".

## OAuth Authorization Server Metadata Registry

This document requests registration of the following parameter in the
IANA OAuth Authorization Server Metadata registry established by
{{RFC8414}}.

| Metadata Parameter | Metadata Description | Change Controller | Reference |
|---|---|---|---|
| `aat_issuer` | Indicates root AAT issuance support | IETF | This document |

`aat_issuer` is a boolean value. When present and `true`, it indicates
that the root issuer supports issuance of AAT root tokens as described
in Section 6.1. When absent, the AS is assumed not to support AAT
issuance.

## OAuth Token Type Registration

This document requests registration of the following token type in the
OAuth Access Token Types registry ({{RFC6749}} Section 11.1):

- Type name: `aat`
- Additional Token Endpoint Response Parameters: (none)
- HTTP Authentication Scheme(s): (none; not a bearer token)
- Change controller: IETF
- Specification document(s): This document

## Media Type Registration

This section registers the `application/aat+jwt` and
`application/aat-pop+jwt` media types in the IANA Media Types registry.

The `typ` header values `aat+jwt` and `aat-pop+jwt` are the JWT type
identifiers corresponding to these media types, following the
structured-syntax convention used by DPoP {{RFC9449}}.

**Type name:** application

**Subtype name:** aat+jwt

**Required parameters:** n/a

**Optional parameters:** n/a

**Encoding considerations:** 8bit; JWT values are encoded as a series
of base64url-encoded values (some of which may be the empty string)
separated by period ('.') characters.

**Security considerations:** See Section 9 of this document.

**Interoperability considerations:** n/a

**Published specification:** This document

**Applications that use this media type:** Applications issuing,
deriving, or verifying Attenuating Authorization Tokens

**Fragment identifier considerations:** n/a

**Additional information:**

- Magic number(s): n/a
- File extension(s): n/a
- Macintosh file type code(s): n/a

**Person & email address to contact for further information:**
Niki Aimable Niyikiza, niki@tenuo.ai

**Intended usage:** COMMON

**Restrictions on usage:** none

**Provisional registration?** No

**Author:** Niki Aimable Niyikiza

**Change controller:** IETF

**Type name:** application

**Subtype name:** aat-pop+jwt

**Required parameters:** n/a

**Optional parameters:** n/a

**Encoding considerations:** 8bit; JWT values are encoded as a series
of base64url-encoded values (some of which may be the empty string)
separated by period ('.') characters.

**Security considerations:** See Section 7 and Section 9 of this document.

**Interoperability considerations:** n/a

**Published specification:** This document

**Applications that use this media type:** Applications producing or
verifying AAT proof-of-possession JWTs

**Fragment identifier considerations:** n/a

**Additional information:**

- Magic number(s): n/a
- File extension(s): n/a
- Macintosh file type code(s): n/a

**Person & email address to contact for further information:**
Niki Aimable Niyikiza, niki@tenuo.ai

**Intended usage:** COMMON

**Restrictions on usage:** none

**Provisional registration?** No

**Author:** Niki Aimable Niyikiza

**Change controller:** IETF

## OAuth Parameters Registry

This document makes no request to the OAuth Parameters Registry. Root
token issuance uses the existing `req_cnf` token request parameter.

# Acknowledgments

The author thanks Alan Karp for detailed review and discussion of
capability-system semantics, confused deputy framing, delegation depth,
revocation, and the relationship between AATs and prior capability
systems.

The author thanks Antoine Fressancourt for review and discussion of
cross-domain privacy, transport binding, remote attestation, and
constraint expressiveness.

The author thanks Igor Kammer Grahl, whose independent implementation
of -01 identified that closed-world mode left no way to constrain an
optional argument and that JCS number canonicalization lets distinct
integers collide, and documented several other places where -01
underdetermined behavior.

The author thanks Neil Madden for review of -01 on the OAuth list,
including the comparison with HMAC-chained Macaroons, replay of parent
and intermediate tokens, the absence of re-keying on attenuation, and
the pointer to SPKI/SDSI.

--- back

# Relationship to DPoP (Non-Normative)

DPoP ({{RFC9449}}) is a token theft prevention mechanism that binds an
existing OAuth access token to a holder key, ensuring that a stolen
token cannot be presented without the corresponding private key. DPoP
does not change what the access token authorizes; the token's
authorization claims are unchanged. The resource server grants whatever
the access token permits; DPoP adds a cryptographic proof that the
presenter holds the bound key.

AATs encode the authorization itself. The token specifies which tools
may be invoked, with what argument constraints, and by which key holder,
and holders can derive tokens with equal or narrower authority without
contacting the authorization server. The PoP JWT in Section 7 serves a
similar cryptographic role to a DPoP proof, binding a specific
invocation to the leaf token's holder key. DPoP, by contrast, is a
two-party protocol between a client and a resource server: it has no
delegation model, parent-child chain, or attenuation invariant, so the
chain model, the invariants, and the constraint registry of this
specification address questions outside its scope.

At the proof level, DPoP binds to an HTTP method (`htm`) and URI
(`htu`). AAT PoP JWTs bind to a tool identifier (`aat_tool`) and a
structured
argument map (`hta`). Tool invocations are function calls, not HTTP
requests, and a URI alone carries insufficient information for
argument-level constraint evaluation, so `aat_tool` names the tool and
`hta` carries the full argument map the enforcement point evaluates, in
place of `htm` and `htu`; `aat_id` names the leaf token being presented.
As DPoP's
`ath` binds a proof to one access token, `aat_hash` binds an AAT PoP
JWT to the exact leaf token, so a token re-derived with the same `jti`
cannot reuse a captured proof.

Two proof-level mechanisms are borrowed from DPoP directly. `aat_aud`
follows the `htu` model of naming the target the proof is presented
to, and the OPTIONAL `nonce` claim follows the DPoP server-provided
nonce ({{RFC9449}} Section 9), so an enforcement point can bind proofs
to itself without the holder knowing its identity (Section 9.5).

The cryptographic mechanism is the same: an asymmetric key in `cnf.jwk`,
compact JWT serialization, verified against the leaf token's bound key.
DPoP could in principle be layered alongside AATs as a transport-level
binding for chain delivery, but that combination is outside the scope of
this specification.

# Implementation Notes (Non-Normative)

## Algorithm Recommendations

The `cnf.jwk` key type is not fixed to Ed25519 (Section 9.12), so
implementations should be designed to support algorithm migration
without changes to token structure.

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
agent and can authenticate it to the token endpoint at root issuance
(Section 6.1.2). The AAT itself binds the agent by its holder key in
`cnf.jwk`; `iss` identifies the root issuer.

## Delegation Depth Guidance

Section 4.3 requires a finite MAX_DELEGATION_DEPTH of at least 8.
The appropriate MAX_DELEGATION_DEPTH depends on the deployment topology.
Linear orchestration chains (root issuer, one or two planning layers,
leaf executor) require few hops. Swarm architectures with dynamic
fan-out, sub-task delegation, or hierarchical agent groups may require
significantly deeper chains.

Regardless of the implementation ceiling, issuers should set
`del_max_depth` to the depth required by the expected workflow, with
margin for subprocess delegation, operational handoffs, and holder-key
handoff. Lower values reduce the number of offline delegation steps
under a grant, but overly tight values can suppress attenuation and
encourage broader token reuse.

## Implementation Size Limits

Sections 3.4 and 4.3 set the normative limits and their recommended
values. Implementations with no specific deployment constraints can
also use these defaults:

| Parameter | Suggested Default |
|---|---|
| Maximum tools per token | 256 |
| Maximum constraints per tool | 64 |
| Maximum tool identifier length | 256 bytes |
| Maximum constraint value length | 4 KiB |

Deployments should document their enforced limits, and interoperating
parties should check that their limits are compatible.

Implementations concerned about parser exposure on unverified
payloads in step 2c of the chain verification algorithm (Section 8)
may extract `jti` using a length-limited byte scan rather than a
full JSON parser, provided the extraction correctly handles JSON
whitespace and string escaping.

A single AAT is typically 1-4 KB when base64url-encoded. Chains of two
or more tokens will commonly exceed the 4-8 KB header size limits
enforced by common reverse proxies and load balancers, resulting in 431
errors, which is why Section 7.4 recommends carrying presentations in a
message body or protocol metadata. For size-constrained environments,
Appendix D notes considerations for a future CBOR/CWT profile.

## Signed Passthrough Metadata

Implementations may include additional JWT claims in AATs beyond those
defined in Section 3, using collision-resistant names for passthrough
metadata such as request trace identifiers or tenant context. Such
claims are integrity-protected within each token, but the base chain
verification algorithm does not preserve or interpret them across
derivation steps, and they carry no authority in derived tokens (Section
3.3). Deployments that require chain-wide preservation of passthrough
metadata must define their own derivation and verification rules, either
through deployment-specific policy or a companion profile.

## TTL Guidance

Expiration is the base specification's built-in limit on authority
(Section 4.4), and short lifetimes bound exposure (Section 9.8). Their
cost is re-issuance frequency, which is low when the root issuer is
available and derivation is offline.

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

The core constraint set is intentionally limited to structural
constraint types with deterministic subsumption rules. Implementers that
need richer expressiveness can define extension constraint types backed
by analyzable authorization policy languages, such as Cedar {{CEDAR}}.
Such an extension must define the runtime `check` predicate, the token
encoding of the policy, and a sound, deterministic subsumption
procedure. The fact that a policy language can decide whether an
invocation is authorized is not, by itself, sufficient for AAT
attenuation; the extension must also define how an enforcement point
determines that a derived policy is no less restrictive than its parent.
Where full containment analysis for such a language exceeds the
polynomial bound in Section 5.1, as solver-based analysis can, the
registration defines a conservative syntactic check for enforcement
points; derivers remain free to use the full analysis offline when
choosing what to derive. This document does not recommend a specific
policy language. The normative requirement is that every extension
registration satisfy the decidable, sound, and deterministic properties
defined in Section 5.1.

# CBOR/CWT Considerations (Non-Normative)

The claim semantics, attenuation invariants, constraint subsumption
rules, and chain verification algorithm defined in this document are
format-agnostic. They describe a protocol, not an encoding. JWT/JWS is
the only fully specified token encoding in this document.

A future CWT/COSE profile could represent the same semantic content
using CBOR Web Tokens {{RFC8392}} and COSE message signing {{RFC9052}}.
Such a profile would need to define CWT claim-key assignments, COSE
algorithm requirements, deterministic CBOR serialization rules per
{{RFC8949}}, the CWT parent token signing input used for `par_hash`, and
the deterministic encoding of PoP `hta` values. This appendix does not
define a CWT serialization, CWT claim-key mapping, COSE algorithm
profile, or CWT `par_hash` signing input. Those details are deferred to
a companion document.

# Test Vectors (Non-Normative)
Byte-exact JWS test vectors for the Section 8 algorithm are published in
the reference implementation's repository: a machine-readable suite
{{AAT-VECTORS}} and a readable companion with its generator
{{AAT-VECTOR-GEN}}. Expected verdicts are computed, not hand-written:
the generator runs every vector through its own implementation of the
Section 8 checks the vectors exercise, which shares no code with Tenuo.
The suite covers the happy-path chains, each attenuation invariant (I1
through I6), closed-world leaf checks, explicit typing, required PoP
audience, composite `all` / `any` subsumption including clause reuse,
optional and unnamed arguments and their attenuation, the remaining core
constraint types (`not_one_of`, `contains`, `subset`, range
inclusivity), and the structural root checks in Section 8 steps 3c, 3d,
3f, 3h, 3k, 3l, 3m, and 3n. Implementers targeting the -01 text should
not treat that suite as a -01 conformance pack: it encodes the -02
changes listed in Appendix G.

This appendix reproduces a minimal subset so that the encoding rules of
Section 3.5, Section 4.6, and Section 7.2 can be checked without
external material. Long lines are folded per {{RFC8792}}. Vector
identifiers (J.1, J.3, J.12) are those of the published suite. Each
vector's expected verdict is what this specification requires; the
failing step it names
follows the order of Section 8 and can differ where that section
permits reordering, so test harnesses compare verdicts.

## Parameters

Each role's Ed25519 key is derived from a 32-byte seed of one repeated
byte: 0x01 for control_plane, 0x02 for orchestrator, 0x03 for worker,
and 0x04 for worker2. Verification time
is 1704067500 (2024-01-01T00:05:00Z). MAX_IAT_SKEW is 30 seconds. The
enforcement point audience is `https://tools.example.com`. The only
trust anchor is the root issuer's key (`control_plane` in the suite),
bound to the issuer
`https://auth.example.com`.

| Role | JWK `x` |
|---|---|
| control_plane | `iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w` |
| orchestrator | `gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q` |
| worker | `7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E` |
| worker2 | `ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw` |

The RFC 7638 thumbprint of the Orchestrator key, computed over its JCS
form (first line), is the second line:

~~~
========== NOTE: '\' line wrapping per RFC 8792 ==========

{"crv":"Ed25519","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiX\
fYPW4_Js5Q"}
aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU
~~~

## Single-Token Chain (Vector J.1)

Root token issued by the root issuer to the Orchestrator, presented
alone (root = leaf) with a PoP from the Orchestrator. Expected: PERMIT.

AAT Protected Header (JCS):

~~~
========== NOTE: '\' line wrapping per RFC 8792 ==========

{"alg":"Ed25519","typ":"aat+jwt"}
~~~
AAT Payload (JCS; this exact byte string is base64url-encoded):

~~~
========== NOTE: '\' line wrapping per RFC 8792 ==========

{"authorization_details":[{"tools":{"read_file":{"path":{"constraint_\
type":"wildcard"}}},"type":"attenuating_agent_token"}],"cnf":{"jwk":{\
"crv":"Ed25519","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYP\
W4_Js5Q"}},"del_depth":0,"del_max_depth":3,"exp":1704070800,"iat":170\
4067200,"iss":"https://auth.example.com","jti":"019471f8-0000-7000-80\
00-000000000001"}
~~~
AAT compact serialization:

~~~
========== NOTE: '\' line wrapping per RFC 8792 ==========

eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYWF0K2p3dCJ9.eyJhdXRob3JpemF0aW9uX2Rl\
dGFpbHMiOlt7InRvb2xzIjp7InJlYWRfZmlsZSI6eyJwYXRoIjp7ImNvbnN0cmFpbnRfd\
HlwZSI6IndpbGRjYXJkIn19fSwidHlwZSI6ImF0dGVudWF0aW5nX2FnZW50X3Rva2VuIn\
1dLCJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZ1R\
sM0RxaDlGMTlXbzFSbXcweC16TXVOaXBHMDdqZWlYZllQVzRfSnM1USJ9fSwiZGVsX2Rl\
cHRoIjowLCJkZWxfbWF4X2RlcHRoIjozLCJleHAiOjE3MDQwNzA4MDAsImlhdCI6MTcwN\
DA2NzIwMCwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwianRpIjoiMDE5ND\
cxZjgtMDAwMC03MDAwLTgwMDAtMDAwMDAwMDAwMDAxIn0.G2ZIeMAY5H1nbG0j2f6R9hW\
8WsP98CC8ZA9-dLpNATy-i7DMR6iAHzgSrAhpdTVt1Y5urMK9iE0ZXMcLHzrHBg
~~~
PoP Payload (JCS):

~~~
========== NOTE: '\' line wrapping per RFC 8792 ==========

{"aat_aud":"https://tools.example.com","aat_hash":"qz05CjO1S-iTk93CGK\
miB8y7bRUdUAe67kXzUwyMzUU","aat_id":"019471f8-0000-7000-8000-00000000\
0001","aat_tool":"read_file","hta":{"path":"/data/q3-report.pdf"},"ia\
t":1704067500,"jti":"019471f8-0000-7000-8000-000000000a01"}
~~~
PoP compact serialization:

~~~
========== NOTE: '\' line wrapping per RFC 8792 ==========

eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYWF0LXBvcCtqd3QifQ.eyJhYXRfYXVkIjoiaH\
R0cHM6Ly90b29scy5leGFtcGxlLmNvbSIsImFhdF9oYXNoIjoicXowNUNqTzFTLWlUazk\
zQ0dLbWlCOHk3YlJVZFVBZTY3a1h6VXd5TXpVVSIsImFhdF9pZCI6IjAxOTQ3MWY4LTAw\
MDAtNzAwMC04MDAwLTAwMDAwMDAwMDAwMSIsImFhdF90b29sIjoicmVhZF9maWxlIiwia\
HRhIjp7InBhdGgiOiIvZGF0YS9xMy1yZXBvcnQucGRmIn0sImlhdCI6MTcwNDA2NzUwMC\
wianRpIjoiMDE5NDcxZjgtMDAwMC03MDAwLTgwMDAtMDAwMDAwMDAwYTAxIn0.Dod0rnn\
_6OlvM2upQlbY0trWOJPM80GEuZn6gUJr0vOmWrjdWEg_voQT-f-iKsgqGJ1KRdQqisbN\
gaNJ5OBOAQ
~~~

## Three-Level Chain Linkage (Vector J.3)

Root (root issuer to Orchestrator, `del_max_depth` 3), L1
(Orchestrator to Worker, `del_max_depth` 2), L2 (Worker to Worker2,
terminal). Expected: PERMIT. The linkage values below are sufficient to
check Section 4.6 against an independent implementation; the full
tokens are in the published suite. The `jti` values of root, L1, and L2
are `019471f8-0000-7000-8000-000000000010`, `...011`, and `...012`.

| Token | SHA-256 of JWS Signing Input (base64url) |
|---|---|
| root | `BR0nHWoCPtlrdOSpY8vPj7ejvLGj1SSJfK97P-ZWV0g` |
| L1 | `3kFpxq53WreeYGKbIxNqnCqjRSmVjwNoHjjZKIuqRw0` |
| L2 | `6JQpH_zCOFYgK-F4EjOrO9yssdlA24Ygm3JRH6stIdk` |

L1 carries `par_hash` equal to the root row above, and L2 carries
`par_hash` equal to the L1 row. L1's `iss` is:

~~~
urn:ietf:params:oauth:jwk-thumbprint:sha-256:
  aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU
~~~

(one string, shown on two lines).

## Chain Splice (Vector J.12)

The same root and holders as J.3, with an L1 that has its own `jti`
and a `par_hash` of `qz05CjO1S-iTk93CGKmiB8y7bRUdUAe67kXzUwyMzUU`, the
digest of a different root token held by the same key. Signature
verification and I1 both pass; the chain is denied at Section 8 step
4q.

# Implementation Status (Non-Normative)

This appendix describes the implementation status of this specification
at the time of submission, per the practice described in {{RFC7942}}.

## Reference Implementation

Tenuo provides a reference implementation of this protocol. The chain
verification algorithm (Section 8) and token derivation procedure
(Section 6.2) are both implemented. Tenuo also includes an
implementation-specific CBOR/COSE wire representation, with Ed25519
signatures carried in COSE_Sign1 structures. That implementation
experience supports the format independence of the core protocol model,
but does not define a fully interoperable CWT profile; the CWT profile
is deferred as described in Appendix D.

The reference implementation's test suite covers monotonicity of the
attenuation invariants under arbitrary sequences, normalization
idempotence across encode/decode round-trips, and agreement between
in-memory and deserialized constraint evaluation.

JWS test vectors for the algorithm in Section 8 are published as
described in Appendix E.

RFC Editor Note: This section will be updated or removed before
publication.

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

RFC Editor Note: This section will be updated or removed before
publication.

# Changes from draft-niyikiza-oauth-attenuating-agent-tokens-01

RFC Editor Note: This section is to be removed before publication.

This revision is reorganized and makes thirteen normative changes,
which are breaking for implementations of -01. The test vectors in
Appendix E encode most of the verifier-side changes.

Normative changes:

- `typ` is required: `aat+jwt` for AATs and `aat-pop+jwt` for PoP JWTs
  (Section 3.5; steps 3a, 4a, and 7a).
- Ed25519 signatures use the `alg` value `"Ed25519"`; `"EdDSA"` is not
  used ({{RFC9864}}; Section 9.12).
- A root token's `iss` must match the issuer of the trust anchor that
  verified it (step 3k).
- PoP JWTs carry `aat_hash`, which binds the proof to the exact leaf
  token (Section 7.2; step 7c).
- Audience and replay: `aat_aud` names the party a proof is presented
  to, AATs may carry `aud`, and PoP JWTs may carry an enforcement-point
  `nonce`; deployments in which several enforcement points accept one
  chain use at least one of these or share `jti` state; tools returning sensitive data
  SHOULD also get replay protection (Sections 7.2, 7.3, and 9.5; steps
  6c, 7d, 7h, and 7i).
- Optional and unnamed arguments: the `optional` member and the
  reserved `"*"` entry, with their attenuation rules (Sections 3.3, 4.5,
  and 9.13; steps 4p and 6b).
- One derived `all` clause may satisfy several parent clauses (Section
  4.5).
- Empty `all` and `any` are invalid in any position (Section 4.5; steps
  3n and 4o).
- Validation: constraint types and well-formedness are checked
  throughout the chain, and a constraint with a member its type does
  not define is rejected; claim types are checked and `hta` is required;
  integers have no fraction or exponent; audiences compare by exact
  string; `contains` and `subset` use set semantics; constraint depth
  counting is defined; numbers must survive the JCS round trip;
  duplicate JSON members are rejected; `crit` is processed; `tools` is
  required; and MAX_DELEGATION_DEPTH is at least 8 (Sections
  3.2, 3.4, 3.5, and 4.3; steps 3, 4, 6b, and 7a-7c).
- Keys: verification keys come only from trust anchors or `cnf.jwk`,
  never from header parameters; a child sent across a process or trust
  boundary is not bound to its parent's key; and entries other than the
  AAT entry carry no authority in derived tokens (Sections 3.3, 3.5,
  and 6.2).
- Root issuance: the granted authorization details attenuate the
  request, and a request with nothing grantable fails with
  `invalid_authorization_details` (Section 6.1.3).
- The presentation object, `aat_chain` and `aat_pop` (Section 7.4).
- Registration: subsumption procedures run in polynomial time (with a
  conservative fallback for expressive languages), registrations state
  their cost and list only valid cross-type pairs, a parent `wildcard`
  subsumes every type, and evaluating an unregistered type is
  non-conforming (Section 5).

Structure and editorial changes, with no change to verifier behavior:

- Sections follow a token's lifecycle. The extension registry moved
  from 3.5 to 5, root issuance from 3.7 to 6.1, derivation from 6 to
  6.2, proof of possession from 5 to 7, and verification from 7 to 8;
  Security Considerations and later sections moved down by one. Within
  Security Considerations, -01's Unknown Constraint Types subsection is
  folded into Sections 3.4 and 9.6, so the subsections after it move
  up by one. The JWS Protected Header requirements are collected in a
  new Section 3.5, and Implementation Status is now Appendix F, after
  the new Test Vectors appendix. Algorithm steps keep their -01 labels;
  steps 6c, 7h, and 7i are new, and the substeps of step 4p are
  restructured for optional and unnamed arguments.
- The Introduction sets out the mechanism and scope. Repeated
  statements of rules are consolidated, and verification checks are
  listed only in Section 8.
  Section 4.5 gives its pairs as a table and uses one subsumption
  direction. The comparison appendix covers only DPoP.
- -01 required chain verification through step 6 before the PoP JWT
  was evaluated; -02 requires steps 1-5 and recommends checking the PoP
  signature before step 6b (Sections 7.3 and 8). Verdicts are unchanged.
- -01's list of PoP checks disagreed with its algorithm on `aat_tool`,
  which must equal the invoked tool, and on `hta`, which is compared
  after JCS canonicalization; -02 follows the algorithm (steps 7e and
  7f), and Section 7.3 now points to it.
- In response to Neil Madden's review of -01: Section 1.3 explains why
  HMAC chaining does not fit and relates AATs to SPKI/SDSI, Section
  9.1.1 covers replay of parent and intermediate tokens, and Section 9.4
  covers re-keying and how destroying the parent's holder key
  approximates it.
- Byte-exact JWS test vectors are published (Appendix E).
