from z3 import *

def prove_theorem(theorem_name, hypothesis, child_accepts, parent_accepts):
    s = Solver()
    s.set("timeout", 15000)  # ms; report UNKNOWN instead of hanging on undecidable fragments
    
    # To prove `hypothesis => (child_accepts => parent_accepts)` globally,
    # we search for ANY assignment (a counterexample) where the hypothesis holds,
    # the child accepts a value, BUT the parent rejects it.
    s.add(hypothesis)
    s.add(child_accepts)
    s.add(Not(parent_accepts))
    
    print(f"Checking {theorem_name}...")
    result = s.check()
    
    if result == unsat:
        print(f"  [+] PROVED: No counterexamples exist globally.")
    elif result == sat:
        print(f"  [-] FAILED: Constraint violation found!")
        print("  [-] Counterexample Model:", s.model())
    else:
        print(f"  [?] UNKNOWN (Timeout or Complex Theory).")


def run_range_proofs():
    print("\n--- Range Constraints ---")
    parent_min, parent_max, child_exact = Ints('parent_min parent_max child_exact')
    value = Int('value')
    
    # Range -> Exact
    # Rigorously prove that if the Exact value is bounded by min/max, 
    # it is mathematically impossible for the child to accept any value the parent rejects.
    hyp_exact = And(child_exact >= parent_min, child_exact <= parent_max)
    
    # Child only accepts the exact value. Parent accepts any value in bounds.
    child_accepts = (value == child_exact)
    parent_accepts = And(value >= parent_min, value <= parent_max)
    
    prove_theorem("Range Subsumes Exact (Strict Value Bound Proof)", hyp_exact, child_accepts, parent_accepts)


def run_cidr_proofs():
    print("\n--- CIDR Constraints ---")
    parent_net, parent_mask = BitVecs('parent_net parent_mask', 32)
    child_net, child_mask = BitVecs('child_net child_mask', 32)
    ip = BitVec('ip', 32)
    
    # Valid CIDR constraint: masks must look like contiguous 1s from MSB.
    # In bitwise math, `~mask + 1` should be a power of 2, AND mask != 0 
    # Or more simply, `(mask & (~mask + 1)) == (mask ^ 0xFFFFFFFF) + 1` handles CIDR bounds trivially.
    # To keep Z3 solving fast without quantifiers over power-of-two, we explicitly say:
    # A mask `m` is a valid CIDR mask if there exists `k` (0..32) such that `m == (0xFFFFFFFF << k)`.
    # Since we operate dynamically, a general bitmask subset check evaluates identically:
    valid_cidr_parent = (parent_mask & (~parent_mask + 1)) == ((~parent_mask) + 1)
    
    # Hyp: Child mask must be stricter (more zeros at LSB -> `child_mask & parent_mask == parent_mask`)
    # And child's network address must fall into parent's network
    hyp_cidr = And(
        valid_cidr_parent,
        (child_net & parent_mask) == (parent_net & parent_mask),
        (child_mask & parent_mask) == parent_mask
    )
    
    child_accepts = (ip & child_mask) == (child_net & child_mask)
    parent_accepts = (ip & parent_mask) == (parent_net & parent_mask)
    
    prove_theorem("CIDR Valid Network Mask Algebra", hyp_cidr, child_accepts, parent_accepts)


def run_cel_proofs():
    print("\n--- CEL Exact Parsing Rules ---")
    # Instead of propositional boolean logic, we model string evaluation using Z3's sequences.
    # The spec invariant relies on appending `&& (child_expr)` and wrapping parent in parentheses.
    # We use an Uninterpreted Function `SatisfiesCEL(expression, state) -> Bool`
    # and provide evaluation axioms to prove `(P) && (C)` always enforces `P`.
    SatisfiesCEL = Function('SatisfiesCEL', StringSort(), StringSort(), BoolSort())
    
    parent_cel = String('parent_cel')
    child_extra = String('child_extra')
    state = String('state')
    
    # The child expression is exactly matching Rust runtime serialization.
    child_cel = Concat(StringVal("("), parent_cel, StringVal(") && ("), child_extra, StringVal(")"))
    
    # Axiom for CEL evaluation: "({A}) && ({B})" evaluates to AND of both.
    cel_axiom = ForAll([parent_cel, child_extra, state],
        SatisfiesCEL(Concat(StringVal("("), parent_cel, StringVal(") && ("), child_extra, StringVal(")")), state) == 
        And(SatisfiesCEL(parent_cel, state), SatisfiesCEL(child_extra, state))
    )
    
    s = Solver()
    s.add(cel_axiom)
    
    # Since `SatisfiesCEL` relies on an uninterpreted axiom, we check satisfiability natively
    hypothesis = True
    child_accepts = SatisfiesCEL(Concat(StringVal("("), parent_cel, StringVal(") && ("), child_extra, StringVal(")")), state)
    parent_accepts = SatisfiesCEL(parent_cel, state)
    
    s.add(hypothesis)
    s.add(child_accepts)
    s.add(Not(parent_accepts))
    print("Checking CEL Parenthesis Evaluation Semantics...")
    res = s.check()
    if res == unsat:
        print("  [+] PROVED: No counterexamples exist globally.")
    else:
        print("  [-] FAILED")

def run_url_proofs():
    print("\n--- UrlPattern String Parsing Algebra ---")
    # UrlPattern subsumption is the conjunction of two independent dimensions:
    # domain-suffix and path-prefix. Z3's sequence theory has no complete
    # decision procedure for SuffixOf AND PrefixOf asserted over the *same*
    # string (it returns unknown/timeout). Subsumption decomposes per
    # dimension, so each dimension is proved separately; both discharge.
    v_url = String('v_url')
    parent_domain, child_domain = Strings('parent_domain child_domain')
    parent_path, child_path = Strings('parent_path child_path')

    # Dimension 1: domain suffix transitivity.
    prove_theorem(
        "UrlPattern Domain-Suffix Transitivity",
        SuffixOf(parent_domain, child_domain),
        SuffixOf(child_domain, v_url),
        SuffixOf(parent_domain, v_url),
    )

    # Dimension 2: path prefix transitivity.
    prove_theorem(
        "UrlPattern Path-Prefix Transitivity",
        PrefixOf(parent_path, child_path),
        PrefixOf(child_path, v_url),
        PrefixOf(parent_path, v_url),
    )

def run_subpath_proofs():
    print("\n--- Subpath (path_containment extension) ---")
    # Subpath / path_containment subsumption: a child path that extends the
    # parent path accepts only values that also start with the parent path.
    v_str = String('v_str')
    parent_str, child_str = Strings('parent_str child_str')

    prove_theorem(
        "Subpath Prefix Transitivity",
        PrefixOf(parent_str, child_str),
        PrefixOf(child_str, v_str),
        PrefixOf(parent_str, v_str),
    )

    # NOTE: regex and glob `pattern` subsumption are intentionally NOT modeled
    # here. They are not core constraint types (see draft Section 3.4), and a
    # substring-containment approximation of regex subsumption is unsound, so
    # it is omitted rather than presented as a proof.

if __name__ == '__main__':
    run_range_proofs()
    run_cidr_proofs()
    run_cel_proofs()
    run_url_proofs()
    run_subpath_proofs()
