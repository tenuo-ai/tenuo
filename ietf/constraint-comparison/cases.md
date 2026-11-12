# The cases

Sixteen cases, grouped by the question they come from.
[cases.json](cases.json) holds each one in full: the same narrowing in each
draft's own syntax, the result, and the section that decides it.

How to read the tables:

- A result is what the draft's text gives today.
- "Open" means no rule deciding the case was found in the text. The draft's
  author may know where it is decided.
- For AAT, a step is the verification step that denies, and an id such as
  J.19.8 is the vector in the -02 suite that covers the rule.
- The asor and hulea columns are a reading of the text that their authors
  have not reviewed yet ([status](README.md#status-and-how-to-add-to-it)).
- Numbers in parentheses are sections of the draft in that column.

## Depth

All three drafts limit depth, and each counts it in its own unit.

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| Claims | `del_depth` and `del_max_depth`, both in every token (3.2) | `del_depth` in every token; `del_max_depth` required in the root (3) | `max_depth`, optional, 0 if absent (4.1) |
| What the limit counts | The greatest `del_depth` a token below may have (4.3) | The tokens in the chain: the leaf's `del_depth` is less than the root's `del_max_depth` (6 step 3) | The sub-delegations still allowed below this mandate (4.1) |
| Rule at each link | The child's depth is the parent's plus 1 and no greater than the parent's limit; the child's limit is no greater than the parent's (4.3) | `del_depth` equals the position in the chain; the child's limit is no greater than the parent's (6 step 3, 4.3 rule 5) | The child's `max_depth` is at most the parent's minus 1 (4.8) |
| A limit a holder lowers | Binds every token below it (4.3) | Must not exceed the parent's; the depth check uses the root's value (6 step 3) | Binds every mandate below it (4.8) |
| Other bound | The verifier's MAX_DELEGATION_DEPTH, at least 8 (4.3) | None | The profile's `max_chain_length` (8) |

These two cases put the same numbers through all three.

| Case | What it tests | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|---|
| CC-1 | A limit of 8, and a leaf eight levels below the root | PERMIT (J.10.f) | DENY, `depth_invalid` | PERMIT |
| CC-2 | A root limit of 8 that a holder lowers to 2, and a token at depth 3 | DENY, step 4e | PERMIT | DENY, `depth_exceeded` |

They are two separate questions.

- **What the limit counts (CC-1).** With a limit of 8 at the root, AAT and
  hulea accept a chain of nine tokens and asor a chain of eight. asor -03
  Section 10 records this difference. Each way of counting is consistent
  inside its own draft.
- **Whether a lowered limit binds (CC-2).** All three require that a child's
  limit not exceed its parent's. AAT and hulea also apply the lower value to
  every token below it, so the limit in force at any token is the lowest on
  its path. asor's depth check uses the root's value.

## Inputs no constraint names

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

## Changing the type

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

## Values

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

## Rerunning the AAT column

[check_aat.py](check_aat.py) builds each case as a signed AAT chain and
checks the recorded result and step against the reference verifier. Run it
with `python3 check_aat.py ../vectors cases.json`. It needs the
`cryptography` package, as `gen_vectors.py` does.

CC-2, CC-8 and CC-11 to CC-14 have no vector in the -02 suite
([INTEROP.md](../vectors/INTEROP.md) describes the suite). J.8.17 and J.8.18
cover the rules behind CC-11 and CC-14 for a root token.
