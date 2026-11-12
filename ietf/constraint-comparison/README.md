# Constraint narrowing in three delegation chain drafts

How may a delegated token narrow a constraint? This compares the rule in
three Internet-Drafts and gives a test case wherever they differ.

| Name here | Draft |
|---|---|
| AAT | [draft-niyikiza-oauth-attenuating-agent-tokens-02](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-02) |
| asor | [draft-asor-wimse-agent-delegation-chain-03](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-03) |
| hulea | [draft-hulea-wimse-agent-mandate-01](https://datatracker.ietf.org/doc/html/draft-hulea-wimse-agent-mandate-01) |

This is a working document, written by the author of AAT. The asor and
hulea columns are a reading of the text that their authors have not
reviewed yet, and an author's own reading replaces it. A difference is not a
fault in either draft, and nothing here ranks them.

## Where the three agree

- A child's set of allowed values is a subset of its parent's.
- A bound can only tighten.
- Expiry can only shorten.
- A child never drops a restriction its parent set.
- A constraint type the verifier does not implement never widens what is
  allowed.

Three ways of narrowing work in all three: a set narrowed to a smaller set,
a number pinned by tightening both bounds, and an object pinned with a
one-element set.

## Where they differ

| Question | AAT -02 | asor -03 | hulea -01 | Cases |
|---|---|---|---|---|
| What a depth limit of 8 allows | Nine tokens | Eight tokens | Nine mandates | CC-1 |
| A limit that a holder lowers | Binds the tokens below it | The depth check uses the root's value | Binds the mandates below it | CC-2 |
| An input no constraint names | Denied, unless the map has `"*"` | Unbounded | Rejected, unless the Type Profile admits it | CC-3a to CC-6 |
| Replacing a constraint with one of another type | A `range` or a `one_of`, by an `exact` | No; each key and type is kept | An `in`, by an `eq` | CC-7, CC-10 |
| A single-value type | `exact`, scalars only | None; a one-element `one_of` | `eq`, any JSON value | CC-10, CC-14 |
| An empty set | Denied | No rule found in the text | Malformed | CC-11 |
| 1.0 where the parent wrote 1 | Equal | A payload has one spelling | Not identical | CC-12 |

## Read further

| Page | What it has |
|---|---|
| [cases.md](cases.md) | The sixteen cases, grouped by question, with each draft's result |
| [rules.md](rules.md) | Where a constraint attaches, and the narrowing rule for each kind |
| [exact-request.md](exact-request.md) | Binding one exact request: pinning, proofs, approval, revocation and state |
| [cases.json](cases.json) | Each case in every draft's own syntax, with the section that decides it |
| [check_aat.py](check_aat.py) | Reruns the AAT column through the reference verifier |

[draft-sweeney-wimse-credential-delegation-02](https://datatracker.ietf.org/doc/html/draft-sweeney-wimse-credential-delegation-02)
takes its constraint types and narrowing rules from asor, so the asor column
covers them. [exact-request.md](exact-request.md#credential-delegation--02)
says what is particular to it.

## Status, and how to add to it

| Column | Where it comes from | Reviewed by the draft's author |
|---|---|---|
| AAT | Run through the -02 reference verifier ([gen_vectors.py](../vectors/gen_vectors.py)) | Yes |
| asor | Read from the -03 text | Not yet |
| hulea | Read from the -01 text | Not yet |

Corrections and additions are welcome from anyone, and most of all from the
authors of the drafts. An issue, a pull request or a message on the OAuth
list is enough.

- **Correct a cell.** Say what the text means and which section decides it.
  The column is then marked as reviewed.
- **Add a case.** Each case in [cases.json](cases.json) has one entry for
  each draft.
- **Add a check for your column.** A script like [check_aat.py](check_aat.py)
  for another draft's implementation can sit beside it.
- **Add a draft.** One that defines its own narrowing rules can have a
  column.
- **Cover what only one draft has.** `prefix`, `rank`, `max_lifetime` and
  `max_subtree` in asor, and `window`, `sum_max` and `cosign_above` in
  hulea, have no case yet, because no second draft has a counterpart.

If the authors would rather keep this somewhere neutral, it can move.
