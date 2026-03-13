module aat_constraints

// --- Universe of Values ---
sig Value {}

sig ListValue extends Value {
    elements: set Value
}

// --- Constraint Definition ---
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

// "Contains" (List must contain specified values)
sig Contains extends Constraint {
    required: set Value
} {
    accepts = { l: ListValue | required in l.elements }
}

// "Subset" (List is a subset of allowed values)
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
    any_clauses: set Constraint
} {
    accepts = { v: Value | some c: any_clauses | v in c.@accepts }
}

sig All extends Constraint {
    all_clauses: set Constraint
} {
    accepts = { v: Value | all c: all_clauses | v in c.@accepts }
}


// --- Single Step Bounded Unrolling for Recursive Subsumption ---
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
        // NotOneOf must strictly grow the denied set to shrink the accepted set
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
        parent in Not => {
            // Subsumption logic is reversed for NOT
            child.inner -> parent.inner in sub
        } else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in Any => {
        parent in Any => {
            // "Type-keyed positional matching" - removing clauses allowed, adding forbidden.
            // Modeled as: An injective mapping from child clauses to parent clauses
            // WHERE the child clause and the matched parent clause MUST be the exact same type.
            all c: child.any_clauses | one p: parent.any_clauses | {
                p -> c in sub
                // Enforce strict Type-Keying:
                (p in Exact <=> c in Exact)
                (p in Wildcard <=> c in Wildcard)
                (p in OneOf <=> c in OneOf)
                (p in NotOneOf <=> c in NotOneOf)
                (p in Contains <=> c in Contains)
                (p in Subset <=> c in Subset)
                (p in Not <=> c in Not)
                (p in Any <=> c in Any)
                (p in All <=> c in All)
            }
            all p: parent.any_clauses | lone c: child.any_clauses | p -> c in sub
        } else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    child in All => {
        parent in All => {
            // "Type-keyed positional matching" - Every parent clause must be matched
            // to a distinct child clause that attenuates it.
            // Modeled as: An injective mapping from parent clauses to child clauses.
            // WHERE the parent clause and matched child clause MUST be the exact same type.
            all p: parent.all_clauses | one c: child.all_clauses | {
                p -> c in sub
                // Enforce strict Type-Keying:
                (p in Exact <=> c in Exact)
                (p in Wildcard <=> c in Wildcard)
                (p in OneOf <=> c in OneOf)
                (p in NotOneOf <=> c in NotOneOf)
                (p in Contains <=> c in Contains)
                (p in Subset <=> c in Subset)
                (p in Not <=> c in Not)
                (p in Any <=> c in Any)
                (p in All <=> c in All)
            }
            all c: child.all_clauses | lone p: parent.all_clauses | p -> c in sub
        } else
        parent in Wildcard => always_true[] else
        cannot_subsume[]
    } else
    cannot_subsume[]
}

fun sub1 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, none->none]} }
fun sub2 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub1]} }
fun sub3 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub2]} }
fun sub4 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub3]} }
fun sub5 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub4]} }
fun sub6 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub5]} }
fun sub7 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub6]} }
fun sub8 : Constraint->Constraint { {p, c: Constraint | subsumes_step[p, c, sub7]} }

pred always_true[] {}
pred cannot_subsume[] { some none }

// --- Induction Limits & Claims ---
// The following assertion explicitly states that IF the structural 
// depth-bound relations (up to depth 8 nesting) determine that child attenuates parent, 
// THEN the logical constraint capability is mathematically monotone (child ⊆ parent).
assert CapabilityMonotonicity {
    all parent, child: Constraint |
        parent->child in sub8 => (child.accepts in parent.accepts)
}

// We prove this mathematically by asking Alloy to search the entire state space combinatorics 
// up to 8 Constraints and 8 Values. If unsatisfiable, no counterexample exists inside this bound.
check CapabilityMonotonicity for 8 Constraint, 8 Value
