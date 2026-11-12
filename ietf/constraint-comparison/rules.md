# The narrowing rules

Numbers in parentheses are sections of the draft in that column. The asor and hulea columns are a reading of the text that their
authors have not reviewed yet
([status](README.md#status-and-how-to-add-to-it)).

## Where a constraint attaches

| | AAT -02 | asor -03 | hulea -01 |
|---|---|---|---|
| What is authorized | A tool, named by an identifier compared as an exact string (3.3) | A scope string: literal, wildcard such as `crm.*`, or opaque (4.1) | A Permission shaped like an RFC 9396 authorization detail: `type`, plus `locations`, `actions`, `datatypes`, `privileges` and other members (4.4) |
| What a constraint targets | One named argument of the tool (3.3) | A `key` naming a dimension of the action (4.2) | A JSON Pointer `ptr` into the requested authorization detail (4.5) |
| Constraints per target | One; `all` and `any` combine several (3.4) | One per (key, type); different types on one key all apply (4.2) | Several per pointer; all apply (4.4 rule 5) |
| An input no constraint names | Denied, unless the map has `"*"` (3.3) | Unbounded (4.3 rule 3) | Rejected, unless the Type Profile admits the member (4.4 rule 4, 8.1) |
| Numbers | JSON numbers that survive a JCS round trip (3.4) | JSON numbers, with integers up to 2^53-1; the payload must be JCS (3) | Decimal strings for amounts; JSON numbers are discouraged (4.5, 4.6) |
| Narrowing what is authorized | The child's tools are a subset of the parent's (4.5) | Each child scope is covered by a parent scope (4.3 rule 1) | Same `type`; the four array members shrink; other members stay identical (4.7 rules 1 to 4) |

## The rule for each kind of constraint

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

Each draft has kinds of constraint the others lack: exclusive bounds,
`contains`, `subset`, `all` and `any` in AAT; `prefix`, `rank`,
`max_lifetime` and `max_subtree` in asor; `window`, `sum_max` and
`cosign_above` in hulea.
