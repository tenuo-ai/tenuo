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
