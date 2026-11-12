# Constraint narrowing in three delegation chain drafts

This note compares how a delegated token may narrow a constraint in three
Internet-Drafts.

| Name used here | Draft |
|---|---|
| AAT | [draft-niyikiza-oauth-attenuating-agent-tokens-02](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-02) |
| asor | [draft-asor-wimse-agent-delegation-chain-03](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-03) |
| hulea | [draft-hulea-wimse-agent-mandate-01](https://datatracker.ietf.org/doc/html/draft-hulea-wimse-agent-mandate-01) |

[draft-sweeney-wimse-credential-delegation-02](https://datatracker.ietf.org/doc/html/draft-sweeney-wimse-credential-delegation-02)
(Cred below) takes its constraint types and narrowing rules from asor (its
Section 5.3), so the asor column gives its narrowing rules too. Section 5.5
below says what differs for it.

For each kind of constraint, the note gives the rule each draft applies
between a parent token and a child token. Where the drafts differ, it gives a
case: the same narrowing in each draft's own syntax, with the result each
draft gives. The cases are in [cases.json](cases.json).

## Status

This is a working document. It was written by the author of AAT, so the AAT
column is the one most likely to be right, and the other two are the ones
most likely to need correcting.

| Column | Where it comes from | Reviewed by the draft's author |
|---|---|---|
| AAT | Run through the -02 reference verifier ([gen_vectors.py](../vectors/gen_vectors.py)); [check_aat.py](check_aat.py) reruns it | Yes |
| asor | Read from the -03 text; each result names the section that decides it | Not yet |
| hulea | Read from the -01 text; each result names the section that decides it | Not yet |
| Cred (Section 5.5) | Read from the -02 text; the exact-request entry is its author's, from the OAuth list | In part |

The asor and hulea columns are one reader's understanding of someone else's
draft, and they have not been run against an implementation. Where an author
reads their own text differently, the author's reading goes in and the
column is marked as reviewed. Section 6 says how.

A difference in a table is not a fault in either draft. The drafts start
from different places, and Sections 1 to 3 describe those starting points
before Section 4 shows where they lead. The note compares one narrow thing:
how a constraint narrows from one token to the next. It does not rank the
drafts, and it leaves out most of what each of them is for.

Where the -02 suite already has a vector for an AAT rule, its id is given,
for example J.19.8. Section numbers are each draft's own. Columns are in
alphabetical order.

## Summary

The three drafts agree on the main rules:

- A child's set of allowed values is a subset of its parent's.
- A child's upper bound is no greater than its parent's, and its lower bound
  no less.
- A child's expiry is no later than its parent's.
- A child never drops a restriction its parent set.
- A constraint type the verifier does not implement never widens what is
  allowed.

They answer six questions differently, and each has a case in Section 4:

1. What the depth limit counts (CC-1).
2. Whether a limit lowered by a holder binds the tokens below it (CC-2).
3. What happens to an input no constraint names (CC-3a to CC-6).
4. Whether a child may replace a constraint with one of another type (CC-7,
   CC-10).
5. Whether there is a single-value type, and what it may hold (CC-10, CC-14).
6. Whether a set may be empty, and how two spellings of one number compare
   (CC-11, CC-12).

Three ways of narrowing are accepted by all three: a set narrowed to a
smaller set (CC-9), a number pinned by tightening both bounds (CC-8), and an
object pinned with a one-element set (CC-13).

Each draft also has kinds of constraint the others lack: exclusive bounds,
`contains`, `subset`, `all` and `any` in AAT; `prefix`, `rank`,
`max_lifetime` and `max_subtree` in asor; `window`, `sum_max` and
`cosign_above` in hulea.

## 1. Where a constraint attaches

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| What is authorized | A tool, named by an identifier compared as an exact string (3.3) | A scope string: literal, wildcard such as `crm.*`, or opaque (4.1) | A Permission shaped like an RFC 9396 authorization detail: `type`, plus `locations`, `actions`, `datatypes`, `privileges` and other members (4.4) |
| What a constraint targets | One named argument of the tool (3.3) | A `key` naming a dimension of the action (4.2) | A JSON Pointer `ptr` into the requested authorization detail (4.5) |
| Constraints per target | One; `all` and `any` combine several (3.4) | One per (key, type); different types on one key all apply (4.2) | Several per pointer; all apply (4.4 rule 5) |
| An input no constraint names | Denied, unless the map has `"*"` (3.3) | Unbounded (4.3 rule 3) | Rejected, unless the Type Profile admits the member (4.4 rule 4, 8.1) |
| Numbers | JSON numbers that survive a JCS round trip (3.4) | JSON numbers, with integers up to 2^53-1; the payload must be JCS (3) | Decimal strings for amounts; JSON numbers are discouraged (4.5, 4.6) |
| Narrowing what is authorized | The child's tools are a subset of the parent's (4.5) | Each child scope is covered by a parent scope (4.3 rule 1) | Same `type`; the four array members shrink; other members stay identical (4.7 rules 1 to 4) |

## 2. The narrowing rule for each kind of constraint

Each cell names the type and says what a child must carry. "None" means the
draft defines no such type. Often it reaches the same result another way,
and the cell then says how.

| Kind | AAT -02 (3.4, 4.5) | asor -03 (4.2, 4.3) | hulea -01 (4.5, 4.7) |
|---|---|---|---|
| One value | `exact`, a scalar. Child: `exact` with the same value. | None. A one-element `one_of` does the same. | `eq`, any JSON value. Child: `eq` with an identical value. |
| A set of values | `one_of`. Child: `one_of` with a non-empty subset, or `exact` with a member. | `one_of`. Child: `one_of` with a subset. | `in`, non-empty. Child: `in` with a subset, or `eq` with an element. |
| Excluded values | `not_one_of`. Child: `not_one_of` with a superset. | `not_one_of`. Child: `not_one_of` with a superset. | None. |
| Upper bound | `range` with `max`. Child: `range` with a `max` no greater, or `exact` with a number in the range. | `max`. Child: `max` no greater. | `max`. Child: `max` no greater. |
| Lower bound | `range` with `min`. Child: `range` with a `min` no less, or `exact` with a number in the range. | `min`. Child: `min` no less. | `min`. Child: `min` no less. |
| Exclusive bound | `min_inclusive` and `max_inclusive` on `range`. Child: at an equal bound, not inclusive where the parent's is exclusive. | None. | None. |
| Array must include | `contains`. Child: `contains` with a superset of the required elements. | None. | None. |
| Array limited to | `subset`. Child: `subset` with a subset of the allowed elements. | None. | None. |
| String prefix | None in the core. Extension types are registered (5). | `prefix`. Child: a string that begins with the parent's. | None. |
| Position in an ordered list | None. | `rank` with `order`. Child: the same `order`, and a `rank` no higher. | None. |
| Any value | `wildcard`. Child: any constraint. | No constraint on the key. Child: may add one. | No constraint on an admitted member. Child: may add one (4.7 rule 5). |
| All of several | `all`. Child: `all` in which every parent clause covers at least one child clause. | Several types on one key. Child: each narrowed by its own type's rule. | Several constraints on one pointer. Child: for each of the parent's, one on the same pointer at least as strict (4.7 rule 6). |
| Any of several | `any`. Child: `any` in which every child clause is covered by one parent clause. | None. | None inside a Permission. A mandate's Permissions are alternatives (4.7). |
| Time window | Token lifetime only: the child's `exp` is no later (4.4). | Token lifetime only: the child's `exp` is no later (4.3 rule 4). | `window`. Child: `nbf` no earlier and `exp` no later. Token lifetime as well (4.8). |
| Running totals | None in the core; left to profiles (9.1.2). | `max_lifetime` per token, `max_subtree` per subtree. Child: a value no greater. | `sum_max` per budget and period. Child: the same budget, a value no greater, a period no shorter. |
| Second approval above a threshold | None in the core; left to profiles (9.1.2). | Placed at root issuance (9.7). | `cosign_above`. Child: a value no greater. |
| A type the verifier does not implement | The token is rejected (3.4). | The child is not subsumed unless its copy is byte-identical, and the action is then denied (4.3). | The Permission does not match, and no child constraint counts as at least as strict (4.5). |

## 3. Delegation depth

All three drafts limit depth. They count it in different units.

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| Claims | `del_depth` and `del_max_depth`, both in every token (3.2) | `del_depth` in every token; `del_max_depth` required in the root (3) | `max_depth`, optional, 0 if absent (4.1) |
| What the limit counts | The greatest `del_depth` a token below may have (4.3) | The tokens in the chain: the leaf's `del_depth` is less than the root's `del_max_depth` (6 step 3) | The sub-delegations still allowed below this mandate (4.1) |
| Rule at each link | The child's depth is the parent's plus 1 and no greater than the parent's limit; the child's limit is no greater than the parent's (4.3) | `del_depth` equals the position in the chain; the child's limit is no greater than the parent's (6 step 3, 4.3 rule 5) | The child's `max_depth` is at most the parent's minus 1 (4.8) |
| A limit a holder lowers | Binds every token below it (4.3) | Must not exceed the parent's; the depth check uses the root's value (6 step 3) | Binds every mandate below it (4.8) |
| Other bound | The verifier's MAX_DELEGATION_DEPTH, at least 8 (4.3) | None | The profile's `max_chain_length` (8) |

These are two separate questions, and each has its own case.

- **What the limit counts (CC-1).** With a limit of 8 at the root, AAT and
  hulea accept a chain of nine tokens and asor a chain of eight. asor -03
  Section 10 records this difference. Each way of counting is consistent
  inside its own draft.
- **Whether a lowered limit binds (CC-2).** All three require that a child's
  limit not exceed its parent's. AAT and hulea also apply the lower value to
  every token below it, so the limit in force at any token is the lowest on
  its path. asor's depth check uses the root's value.

## 4. The cases

[cases.json](cases.json) holds each case in full: the same narrowing in each
draft's own syntax, the result, and the section that decides it. The results
are what each text gives today. They are grouped here by the question they
come from.

"Open" means no rule deciding the case was found in the text. The draft's
author may know where it is decided.

### 4.1 Depth

Each draft counts depth in its own unit (Section 3). These two cases put
the same numbers through all three.

| Case | What it tests | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|---|
| CC-1 | A limit of 8, and a leaf eight levels below the root | PERMIT (J.10.f) | DENY, `depth_invalid` | PERMIT |
| CC-2 | A root limit of 8 that a holder lowers to 2, and a token at depth 3 | DENY, step 4e | PERMIT | DENY, `depth_exceeded` |

### 4.2 Inputs no constraint names

The drafts start from different defaults, and each result follows from its
draft's default.

- In AAT a constraint map is closed. An argument it does not name is denied,
  unless the map carries `"*"`. A child may name a new argument only under
  its parent's `"*"`. A child may stop naming an argument its parent marks
  optional, and the argument is then forbidden.
- In asor a key with no constraint is unbounded. A child may add a
  constraint on any key, and may never drop one.
- In hulea a request member must be admitted by the Permission or by the
  Type Profile. A child may add a constraint on an admitted member, and may
  never drop one.

| Case | What it tests | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|---|
| CC-3a | A child constrains an input its parent did not name | DENY, step 4p2 (J.22.15) | PERMIT | DENY, `not_attenuated` |
| CC-3b | The same, where the parent left other inputs open | PERMIT (J.22.13) | PERMIT | PERMIT |
| CC-4a | A request carries an input the leaf does not name | DENY, step 6b (J.9.1) | PERMIT | DENY, `action_not_permitted` |
| CC-4b | The same, where the leaf left other inputs open | PERMIT (J.22.4) | PERMIT | PERMIT |
| CC-5 | A request omits a constrained input | DENY, step 6b (J.9.2) | Open | DENY, `action_not_permitted` |
| CC-6 | A child stops naming an input its parent bounded | PERMIT; the input is then forbidden (J.22.10) | DENY, `not_narrower` | DENY, `not_attenuated` |

### 4.3 Changing the type

AAT lets a child replace a `range` or a `one_of` with an `exact` inside it.
hulea lets a child replace an `in` with an `eq`, and nothing else. asor
keeps each (key, type) pair from parent to child and makes no inference
across types. Every draft has a way to reach the same result: a number
pinned by tightening both bounds (CC-8) and a set narrowed to one element
(CC-9) are accepted by all three.

| Case | What it tests | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|---|
| CC-7 | A bound is replaced by one value inside it | PERMIT (J.19.8) | DENY, `not_narrower` | DENY, `not_attenuated` |
| CC-8 | A number is pinned by tightening both bounds | PERMIT | PERMIT | PERMIT |
| CC-9 | A set is narrowed to one element | PERMIT (J.3) | PERMIT | PERMIT |
| CC-10 | A set is replaced by a single-value constraint | PERMIT (J.3) | No such type; CC-9 is the equivalent | PERMIT |

### 4.4 Values

AAT compares values by their JCS form, so 1.0 and 1 are equal, and its
`exact` holds scalars only. asor requires each payload to be its own JCS
serialization, so a number has one spelling. hulea compares by JSON
identity, under which two numbers are identical only if written the same,
and uses decimal strings for amounts.

| Case | What it tests | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|---|
| CC-11 | A set is narrowed to the empty set | DENY, step 4o | Open | DENY, `malformed` |
| CC-12 | A child writes 1.0 where its parent wrote 1 | PERMIT | DENY, `non_canonical`; written as 1, the child narrows | DENY, `not_attenuated` |
| CC-13 | An object is pinned with a one-element set | PERMIT | PERMIT | PERMIT |
| CC-14 | An object is pinned with a single-value constraint | DENY, step 4o | No such type; CC-13 is the equivalent | PERMIT |

## 5. Pinning one exact request

This section answers a question raised on the OAuth list: can a leaf token
be bound to one exact request? A request can be bound in two ways, and they
are separate entries: in the token itself (5.1), or by a proof that travels
with the request (5.2).

### 5.1 In the token

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| Pin one value from a set | `exact` under `one_of`, or a one-element `one_of` (CC-9, CC-10) | A one-element `one_of` (CC-9) | `eq` under `in`, or a one-element `in` (CC-9, CC-10) |
| Pin a number under a bound | `exact` under `range`, or a `range` whose `min` equals its `max` (CC-7, CC-8) | A `max` and a `min` of the same value (CC-8) | A `max` and a `min` of the same value, or the `max` with an added `eq` (CC-8) |
| Pin an object or an array | A one-element `one_of`; `exact` holds scalars only (CC-13, CC-14) | A one-element `one_of` (CC-13) | `eq`, or a one-element `in` (CC-13, CC-14) |
| Rule out every input the token does not pin | The default: a map without `"*"` (CC-4a) | By naming each input: a key with no constraint is unbounded (CC-4a) | The default, apart from members the Type Profile admits (CC-4a) |
| A constraint on a digest of the request | No such type; a new type needs registering (5) | No such type; a new type needs registering (10) | No such predicate; a new one needs registering (15.4) |

All three can pin every value they name. None has a constraint on a digest
of the whole request.

### 5.2 By a proof that travels with the request

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| The holder's proof at presentation | Covers the tool identifier and the arguments, in a PoP JWT signed with the leaf holder's key (7.2) | A DPoP proof (7), which under RFC 9449 covers the method and the URI | An HTTP message signature that covers the request body through Content-Digest (7.2) |
| A second party's approval of the one request | Not in the core; left to profiles (9.1.2). ARCP, a profile, defines a single-use approval bound to a leaf token, tool and argument set (E.4) | Placed at root issuance (9.7) | `cosign_above`: above the threshold, a second party named by the relying party's policy approves the specific action (9.5) |

None of the three defines the format of a second party's approval. That is
left to a profile, to the relying party's policy, or to a separate
specification.

### 5.3 How fresh revocation state must be

Each cell says when an enforcement point stops admitting new actions under
a revoked token.

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| Mechanism | None in the core. A status mechanism on the root token ends every chain under it (9.8) | An optional Token Status List reference in each token (6 step 7) | Status evidence the relying party checks at authorization time (10.2) |
| A new action is admitted until | The presented token expires. An enforcement point that checks the root's status stops sooner; -02 sets no interval for that check (9.8) | The cached status answer's time to live runs out; after that the verifier denies (6 step 7) | The status evidence is older than the profile's `max_status_age` (8) |

### 5.4 What has to be remembered, and who shares it

Checking a signature needs no memory. Accepting something at most once, or
keeping a total, does. Each cell says what the draft requires to be
remembered, and how far that memory has to be shared.

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| The holder's proof, accepted at most once | A proof names its leaf token (`aat_hash`, 7.2). For tools with side effects, the enforcement point keeps the ids of accepted proofs until they leave the proof window, and replicas of one enforcement point share them (7.3). Where several enforcement points accept the same chain, each shares that state with the others, or requires a nonce, or requires an audience no other accepts (9.5) | A DPoP proof bound to the request (6 step 6), with replay handled as RFC 9449 describes | The authorization server rejects a signature nonce it has already accepted within the signature's validity period (7.2). `aud` restricts where a mandate may be presented (13) |
| A running total | None in the core (9.1.2) | Checked only where the total is held; an enforcement point with no access to it denies (4.2, 6 step 8). Splitting a budget among children needs a single writer (9.4) | The relying party checks and records in one atomic operation (9.5). Relying parties that share no state each enforce the budget separately, so a mandate with `sum_max` should name exactly one of them in `aud` (13) |
| A second party's approval, used at most once | Not in the core; a profile needs its own enforcement state (9.1.2) | Placed at root issuance (9.7) | The relying party discharges the `cosign_above` obligation in the atomic operation that issues a single-use access token (9.5, 10.2) |

### 5.5 Credential Delegation -02

Cred has no column above, because its narrowing rules are asor's. Four
things are particular to it.

- **Where a call is checked.** A call made through the Delegation Server is
  checked there against the operations in the token and against its
  constraints (6.1). No constraint binds a token to a digest of one request,
  so one exact request is not expressible in the token.
- **Revocation.** Through the Delegation Server, a revoked token starts no
  new call once the revocation takes effect, within 1 second for the token
  and 5 seconds for its descendants. Away from the server, no new action is
  admitted after the presented token expires, at most 1 hour after it was
  issued. Both bound the admission of new actions, not the completion of
  actions already admitted (7).
- **Totals.** The Delegation Server is the single writer for running
  totals: it checks and debits them atomically when it authorizes a call
  (5.3, 6.1). Verifiers that each see only some of the calls do not hold the
  total between them (5.5).
- **Tokens verified away from the Delegation Server.** They use asor's
  format by reference (5.5), so the asor column applies to them. Treat that
  entry as provisional: 5.5 leaves parts of the composition to a later
  revision.

## 6. Adding to it

Corrections and additions are welcome from anyone, and most of all from the
authors of the drafts. An issue, a pull request or a message on the OAuth
list is enough.

- **Correct a cell.** Say what the text means and which section decides it.
  An author's reading of their own draft replaces the one here.
- **Add a case.** Each case in [cases.json](cases.json) has one entry for
  each draft. The most useful ones show a difference that no case shows yet.
- **Add a check for your column.** [check_aat.py](check_aat.py) runs the
  AAT entries through a reference verifier. A script that does the same for
  another draft's implementation can sit beside it.
- **Cover what only one draft has.** `prefix`, `rank`, `max_lifetime` and
  `max_subtree` in asor, and `window`, `sum_max` and `cosign_above` in
  hulea, have no case yet, because no second draft has a counterpart to
  compare with.

If the authors would rather keep this somewhere neutral, it can move.

## 7. Files

- [cases.json](cases.json): the sixteen cases. Its `conventions` member
  explains the layout.
- [check_aat.py](check_aat.py): builds each case as a signed AAT chain and
  checks the recorded result and step against the reference verifier. Run it
  with `python3 check_aat.py ../vectors cases.json`. It needs the
  `cryptography` package, as `gen_vectors.py` does.

CC-2, CC-8 and CC-11 to CC-14 have no vector in the -02 suite
([INTEROP.md](../vectors/INTEROP.md) describes the suite). J.8.17 and J.8.18
cover the rules behind CC-11 and CC-14 for a root token.
