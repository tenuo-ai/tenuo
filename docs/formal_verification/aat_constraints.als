module aat_constraints

/*
 * Bounded model of the argument-constraint algebra in
 * draft-niyikiza-oauth-attenuating-agent-tokens-02:
 *
 *   Section 3.3  constraint maps: named keys, `optional`, and "*"
 *   Section 3.4  core constraint types and well-formedness
 *   Section 4.5  subsumption (I4) and the key rules of steps 4p2-4p4
 *
 * The assertions ask whether any derivation the Section 4.5 rules accept
 * can accept a value, or an invocation, that its parent rejects. Alloy
 * searches every instance up to the stated scope; "no counterexample"
 * holds within that scope only and is not a proof for larger sizes.
 *
 * Modeling choices:
 *   - Numbers are small integers (the scope's Int bitwidth).
 *   - Values are compared by identity, standing in for JCS equality.
 *     Arrays are sets, as `contains` and `subset` treat them.
 *   - `range` inclusivity is modeled after the defaults apply.
 *   - The "*" entry is always `wildcard` (Section 3.3), so it is a flag.
 *   - Subsumption is the fixpoint of the Section 4.5 rules. Nesting is
 *     acyclic, so the fixpoint is unique and covers every nesting depth
 *     the scope allows.
 *
 * Run all commands:
 *   java -jar alloy.jar exec -f -o <outdir> aat_constraints.als
 */

// ---------------------------------------------------------------------
// JSON values
// ---------------------------------------------------------------------

abstract sig Value {}
sig Num extends Value { num: one Int }
sig Scalar extends Value {}                 // strings, booleans, null
sig Arr extends Value { elems: set Value }

fact ValuesAreCanonical {
  all disj a, b: Num | a.num != b.num
  all disj a, b: Arr | a.elems != b.elems
  no a: Arr | a in a.^elems
}

one sig True {}

// ---------------------------------------------------------------------
// Core constraint types and their check predicates (Section 3.4)
// ---------------------------------------------------------------------

abstract sig Constraint { accepts: set Value }

sig Exact extends Constraint { val: one Value }
sig Range extends Constraint {
  lo: lone Int, hi: lone Int,
  loIncl: lone True, hiIncl: lone True
}
sig OneOf extends Constraint { values: set Value }
sig NotOneOf extends Constraint { excluded: set Value }
sig Contains extends Constraint { required: set Value }
sig Subset extends Constraint { allowed: set Value }
sig Wildcard extends Constraint {}
sig All extends Constraint { allOf: set Constraint }
sig Any extends Constraint { anyOf: set Constraint }

fun clauses: Constraint -> Constraint { allOf + anyOf }

fact NestingIsFinite { no c: Constraint | c in c.^clauses }

pred aboveLo[r: Constraint, x: Int] {
  no r.lo or (some r.loIncl and x >= r.lo) or (no r.loIncl and x > r.lo)
}

pred belowHi[r: Constraint, x: Int] {
  no r.hi or (some r.hiIncl and x <= r.hi) or (no r.hiIncl and x < r.hi)
}

fact CheckPredicates {
  all c: Exact    | c.accepts = c.val
  all c: Range    | c.accepts = { v: Num | aboveLo[c, v.num] and belowHi[c, v.num] }
  all c: OneOf    | c.accepts = c.values
  all c: NotOneOf | c.accepts = Value - c.excluded
  all c: Contains | c.accepts = { a: Arr | c.required in a.elems }
  all c: Subset   | c.accepts = { a: Arr | a.elems in c.allowed }
  all c: Wildcard | c.accepts = Value
  all c: All      | c.accepts = { v: Value | all k: c.allOf | v in k.accepts }
  all c: Any      | c.accepts = { v: Value | some k: c.anyOf | v in k.accepts }
}

// Section 3.4 well-formedness, applied to a whole constraint tree.
pred wellFormed[c: Constraint] {
  (c in Exact implies c.val in Num + Scalar)
  (c in OneOf implies some c.values)
  (c in Range implies ((some c.lo and some c.hi) implies c.lo <= c.hi))
  (c in Range implies ((no c.lo implies no c.loIncl) and (no c.hi implies no c.hiIncl)))
  (c in All implies some c.allOf)
  (c in Any implies some c.anyOf)
}

pred wf[c: Constraint] { all k: c.*clauses | wellFormed[k] }

// ---------------------------------------------------------------------
// Subsumption rules (Section 4.5), parent -> derived
// ---------------------------------------------------------------------

one sig Rules { sub: Constraint -> Constraint }

pred rangeAtLeastAsTight[p, d: Constraint] {
  (no p.lo or (some d.lo and (d.lo > p.lo or (d.lo = p.lo and (some d.loIncl implies some p.loIncl)))))
  (no p.hi or (some d.hi and (d.hi < p.hi or (d.hi = p.hi and (some d.hiIncl implies some p.hiIncl)))))
}

pred derivable[p, d: Constraint, s: Constraint -> Constraint] {
  (p in Wildcard)
  or (p in Exact and d in Exact and d.val = p.val)
  or (p in Range and d in Range and rangeAtLeastAsTight[p, d])
  or (p in Range and d in Exact and d.val in p.accepts)
  or (p in OneOf and d in OneOf and some d.values and d.values in p.values)
  or (p in OneOf and d in Exact and d.val in p.values)
  or (p in NotOneOf and d in NotOneOf and p.excluded in d.excluded)
  or (p in Contains and d in Contains and p.required in d.required)
  or (p in Subset and d in Subset and d.allowed in p.allowed)
  // every parent clause subsumes at least one derived clause; reuse allowed
  or (p in All and d in All and (all pc: p.allOf | some dc: d.allOf | pc -> dc in s))
  // every derived clause is subsumed by at least one parent clause
  or (p in Any and d in Any and (all dc: d.anyOf | some pc: p.anyOf | pc -> dc in s))
}

fact SubsumptionIsSection45 {
  all p, d: Constraint | (p -> d in Rules.sub) iff derivable[p, d, Rules.sub]
}

assert DerivedConstraintNarrows {
  all p, d: Constraint |
    (wf[p] and wf[d] and p -> d in Rules.sub) implies d.accepts in p.accepts
}

check DerivedConstraintNarrows for 6 but 4 Int, 0 Key, 0 CMap, 0 Args

// ---------------------------------------------------------------------
// Constraint maps and the key rules (Sections 3.3 and 4.5, step 4p)
// ---------------------------------------------------------------------

sig Key {}

sig CMap {
  named: Key -> lone Constraint,
  optional: set Key,
  star: lone True
}

sig Args { arg: Key -> lone Value }

fun keysOf[m: CMap]: set Key { m.named.Constraint }

fact MapsAreWellFormed {
  all m: CMap | m.optional in keysOf[m]
  all m: CMap, c: Key.(m.named) | wf[c]
}

// An empty map is equivalent to {"*": {"constraint_type": "wildcard"}}.
pred hasStar[m: CMap] { some m.star or no m.named }

// Step 6b: closed world, with "*" admitting unnamed arguments.
pred invocationAllowed[m: CMap, a: Args] {
  all k: a.arg.Value |
    (k in keysOf[m] and a.arg[k] in m.named[k].accepts) or (k not in keysOf[m] and hasStar[m])
  all k: keysOf[m] - m.optional | k in a.arg.Value
}

pred keyRulesHold[p, d: CMap] {
  // 4p2
  (some keysOf[d] - keysOf[p]) implies hasStar[p]
  all k: keysOf[p] - keysOf[d] | k in p.optional and not hasStar[d]
  hasStar[d] implies hasStar[p]
  // 4p3
  all k: keysOf[p] & keysOf[d] | k not in p.optional implies k not in d.optional
  // 4p4; a key named only under the parent's "*" meets wildcard, which subsumes every type
  all k: keysOf[p] & keysOf[d] | p.named[k] -> d.named[k] in Rules.sub
}

assert DerivedMapNarrows {
  all p, d: CMap, a: Args |
    (keyRulesHold[p, d] and invocationAllowed[d, a]) implies invocationAllowed[p, a]
}

assert ChainNarrows {
  all r, m, l: CMap, a: Args |
    (keyRulesHold[r, m] and keyRulesHold[m, l] and invocationAllowed[l, a])
      implies invocationAllowed[r, a]
}

check DerivedMapNarrows for 4 but 4 Int, 3 Key, 2 CMap, 1 Args
check ChainNarrows for 4 but 4 Int, 3 Key, 3 CMap, 1 Args

// ---------------------------------------------------------------------
// Non-vacuity: each accepted derivation shape below must have an instance
// ---------------------------------------------------------------------

// The -02 rule: one derived `exact` clause satisfies two parent clauses.
run AllClauseReuse {
  some p, d: All | wf[p] and wf[d] and p -> d in Rules.sub
    and #p.allOf = 2 and no p.allOf & Wildcard and d.allOf in Exact and #d.allOf = 1
} for 5 but 4 Int, 0 Key, 0 CMap, 0 Args

run AnyWithCrossTypeClause {
  some p, d: Any | wf[p] and wf[d] and p -> d in Rules.sub and some Value - p.accepts
    and some d.anyOf & Exact and some p.anyOf & OneOf
} for 5 but 4 Int, 0 Key, 0 CMap, 0 Args

run RangeNarrowedToExact {
  some p: Range, d: Exact | wf[p] and wf[d] and p -> d in Rules.sub and some p.lo and some p.hi
} for 4 but 4 Int, 0 Key, 0 CMap, 0 Args

run ExclusiveBoundUnderInclusive {
  some p, d: Range | wf[p] and wf[d] and p -> d in Rules.sub
    and some p.lo and p.lo = d.lo and some p.loIncl and no d.loIncl
} for 4 but 4 Int, 0 Key, 0 CMap, 0 Args

run NewKeyUnderStar {
  some p, d: CMap, a: Args | keyRulesHold[p, d] and some keysOf[p] and invocationAllowed[d, a]
    and some k: keysOf[d] - keysOf[p] | d.named[k] not in Wildcard
} for 4 but 4 Int, 3 Key, 2 CMap, 1 Args

run OptionalKeyDropped {
  some p, d: CMap, a: Args | keyRulesHold[p, d] and some keysOf[p] - keysOf[d]
    and invocationAllowed[d, a]
} for 4 but 4 Int, 3 Key, 2 CMap, 1 Args

// Conservatism (Section 4.1): the rules reject some derivations that do
// narrow, such as an `exact` under a parent `any`.
run ExactUnderAnyRejected {
  some p: Any, d: Exact | wf[p] and wf[d] and d.accepts in p.accepts and p -> d not in Rules.sub
} for 4 but 4 Int, 0 Key, 0 CMap, 0 Args
