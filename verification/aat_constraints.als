module aat_constraints

sig Value {}

abstract sig Constraint {
    accepts: set Value
}

sig Exact extends Constraint {
    target: one Value
} {
    accepts = target
}

sig Wildcard extends Constraint {} {
    accepts = Value
}

sig OneOf extends Constraint {
    allowed: set Value
} {
    accepts = allowed
}

sig NotOneOf extends Constraint {
    denied: set Value
} {
    accepts = Value - denied
}

// Model for list values used by Contains and Subset
sig ListValue extends Value {
    elements: set Value
}

// Model for "Contains" (List must contain specified values)
sig Contains extends Constraint {
    required: set Value
} {
    accepts = { l: ListValue | required in l.elements }
}

// Model for "Subset" (List is a subset of allowed values)
sig Subset extends Constraint {
    allowed_superset: set Value
} {
    accepts = { l: ListValue | l.elements in allowed_superset }
}

sig Not extends Constraint {
    inner: one Constraint
} {
    accepts = Value - this.@inner.@accepts
}

sig Any extends Constraint {
    clauses: set Constraint
} {
    accepts = { v: Value | some c: clauses | v in c.@accepts }
}

sig All extends Constraint {
    clauses: set Constraint
} {
    accepts = { v: Value | all c: clauses | v in c.@accepts }
}


pred subsumes_step[parent, child: Constraint, sub: Constraint->Constraint] {
    child in Exact => {
        parent in Exact    => child.target = parent.target else
        parent in Wildcard => always_true[] else
        parent in OneOf    => child.target in parent.allowed else
        cannot_subsume[]
    } else
    child in Wildcard => {
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in OneOf => {
        parent in OneOf    => child.allowed in parent.allowed else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in NotOneOf => {
        parent in NotOneOf => parent.denied in child.denied else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in Contains => {
        parent in Contains => parent.required in child.required else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in Subset => {
        parent in Subset => child.allowed_superset in parent.allowed_superset else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in Not => {
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in Any => {
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in All => {
        parent in All => {
            all c_parent: parent.(All <: clauses) | 
                some c_child: child.(All <: clauses) | 
                    c_parent -> c_child in sub
        } else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    cannot_subsume[]
}

fun sub1 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, none->none]} }
fun sub2 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub1]} }
fun sub3 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub2]} }

pred always_true[] {}
pred cannot_subsume[] { some none }

// Use depth 3 for verification
assert CapabilityMonotonicity {
    all parent, child: Constraint |
        parent->child in sub3 => (child.accepts in parent.accepts)
}

// The implementation is intentionally conservative: it rejects some
// semantically safe attenuations (e.g. NotOneOf->Exact, cross-type pairs)
// to keep the lattice simple and auditable. This predicate enumerates the
// conservatism gap rather than asserting its absence.
pred conservatism_gap[parent, child: Constraint] {
    child.accepts in parent.accepts
    parent->child not in sub3
}

check CapabilityMonotonicity for 8 Constraint, 8 Value
run conservatism_gap for 8 Constraint, 8 Value

// ============================================================================
// Map-level keyset identity (I4, IETF draft Section 4.5)
// ============================================================================
//
// Per-constraint subsumption (above) proves that individual constraint
// values narrow correctly. This section models the *map-level* rule:
// when the parent's constraint map is non-empty, the child must have
// exactly the same set of argument keys. Dropping a key reopens that
// argument (escalation under closed-world semantics). Adding a key
// produces invocations the parent's closed-world check rejects (the
// derived invocation set is disjoint, not a subset).

sig ArgKey {}

sig ConstraintMap {
    entries: ArgKey -> lone Constraint
}

fun keys[m: ConstraintMap] : set ArgKey {
    m.entries.Constraint
}

fun non_empty[m: ConstraintMap] : set ConstraintMap {
    { cm: ConstraintMap | some cm.entries }
}

pred map_subsumes[parent, child: ConstraintMap] {
    // Tool-level: child keys must be a subset (no phantom tools)
    // Key-level: when parent is non-empty, exact key set identity
    some parent.entries =>
        keys[child] = keys[parent]
    else
        // Parent empty (open-world): child may introduce any keys
        keys[child] in ArgKey

    // Per-key: each child constraint subsumes its parent's
    all k: keys[parent] & keys[child] |
        parent.entries[k] -> child.entries[k] in sub3
}

// If map_subsumes holds, then every value accepted by the child map
// under closed-world semantics is also accepted by the parent map.
// Closed-world: a value is a map from ArgKey to Value; it is accepted
// iff (a) its keys exactly equal the map's keys, and (b) each value
// satisfies its constraint.

pred map_accepts[m: ConstraintMap, args: ArgKey -> one Value] {
    some m.entries =>
        (args.Value = keys[m] and
         all k: keys[m] | args[k] in m.entries[k].accepts)
    else
        // Empty map: open-world, all arg combinations accepted
        all k: args.Value | some args[k]
}

assert MapMonotonicity {
    all parent, child: ConstraintMap, args: ArgKey -> one Value |
        (map_subsumes[parent, child] and map_accepts[child, args])
            => map_accepts[parent, args]
}

check MapMonotonicity for 4 Constraint, 4 Value, 3 ArgKey, 4 ConstraintMap
