# Binding one exact request

Can a leaf token be bound to one exact request? The question was raised on
the OAuth list, along with what the drafts say about approval, revocation
and state around it. A request can be bound in two ways, and they are
separate entries: in the token itself, or by a proof that travels with the
request.

Numbers in parentheses are sections of the draft in that column. The asor and hulea columns are a reading of the text that their
authors have not reviewed yet
([status](README.md#status-and-how-to-add-to-it)).

## In the token

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| Pin one value from a set | `exact` under `one_of`, or a one-element `one_of` (CC-9, CC-10) | A one-element `one_of` (CC-9) | `eq` under `in`, or a one-element `in` (CC-9, CC-10) |
| Pin a number under a bound | `exact` under `range`, or a `range` whose `min` equals its `max` (CC-7, CC-8) | A `max` and a `min` of the same value (CC-8) | A `max` and a `min` of the same value, or the `max` with an added `eq` (CC-8) |
| Pin an object or an array | A one-element `one_of`; `exact` holds scalars only (CC-13, CC-14) | A one-element `one_of` (CC-13) | `eq`, or a one-element `in` (CC-13, CC-14) |
| Rule out every input the token does not pin | The default: a map without `"*"` (CC-4a) | By naming each input: a key with no constraint is unbounded (CC-4a) | The default, apart from members the Type Profile admits (CC-4a) |
| A constraint on a digest of the request | No such type; a new type needs registering (5) | No such type; a new type needs registering (10) | No such predicate; a new one needs registering (15.4) |

All three can pin every value they name. None has a constraint on a digest
of the whole request.

## By a proof that travels with the request

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| The holder's proof at presentation | Covers the tool identifier and the arguments, in a PoP JWT signed with the leaf holder's key (7.2) | A DPoP proof (7), which under RFC 9449 covers the method and the URI | An HTTP message signature that covers the request body through Content-Digest (7.2) |
| A second party's approval of the one request | Not in the core; left to profiles (9.1.2). ARCP, a profile, defines a single-use approval bound to a leaf token, tool and argument set (E.4) | Placed at root issuance (9.7) | `cosign_above`: above the threshold, a second party named by the relying party's policy approves the specific action (9.5) |

None of the three defines the format of a second party's approval. That is
left to a profile, to the relying party's policy, or to a separate
specification.

## How fresh revocation state must be

Each cell says when an enforcement point stops admitting new actions under
a revoked token.

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| Mechanism | None in the core. A status mechanism on the root token ends every chain under it (9.8) | An optional Token Status List reference in each token (6 step 7) | Status evidence the relying party checks at authorization time (10.2) |
| A new action is admitted until | The presented token expires. An enforcement point that checks the root's status stops sooner; -02 sets no interval for that check (9.8) | The cached status answer's time to live runs out; after that the verifier denies (6 step 7) | The status evidence is older than the profile's `max_status_age` (8) |

## What has to be remembered, and who shares it

Checking a signature needs no memory. Accepting something at most once, or
keeping a total, does. Each cell says what the draft requires to be
remembered, and how far that memory has to be shared.

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| The holder's proof, accepted at most once | A proof names its leaf token (`aat_hash`, 7.2). For tools with side effects, the enforcement point keeps the ids of accepted proofs until they leave the proof window, and replicas of one enforcement point share them (7.3). Where several enforcement points accept the same chain, each shares that state with the others, or requires a nonce, or requires an audience no other accepts (9.5) | A DPoP proof bound to the request (6 step 6), with replay handled as RFC 9449 describes | The authorization server rejects a signature nonce it has already accepted within the signature's validity period (7.2). `aud` restricts where a mandate may be presented (13) |
| A running total | None in the core (9.1.2) | Checked only where the total is held; an enforcement point with no access to it denies (4.2, 6 step 8). Splitting a budget among children needs a single writer (9.4) | The relying party checks and records in one atomic operation (9.5). Relying parties that share no state each enforce the budget separately, so a mandate with `sum_max` should name exactly one of them in `aud` (13) |
| A second party's approval, used at most once | Not in the core; a profile needs its own enforcement state (9.1.2) | Placed at root issuance (9.7) | The relying party discharges the `cosign_above` obligation in the atomic operation that issues a single-use access token (9.5, 10.2) |

## Credential Delegation -02

[draft-sweeney-wimse-credential-delegation-02](https://datatracker.ietf.org/doc/html/draft-sweeney-wimse-credential-delegation-02) (Cred) has no column, because its narrowing rules are asor's. Four
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
