from z3 import *

def prove_theorem(theorem_name, hypothesis, conclusion):
    s = Solver()
    theorem = Implies(hypothesis, conclusion)
    s.add(Not(theorem))
    
    print(f"Checking {theorem_name}...")
    result = s.check()
    
    if result == unsat:
        print(f"  [+] PROVED: No counterexamples exist.")
    elif result == sat:
        print(f"  [-] FAILED: Constraint violation found!")
        print("  [-] Counterexample Model:", s.model())
    else:
        print(f"  [?] UNKNOWN: Solver could not determine satisfiability.")


def run_range_proofs():
    print("\n--- Range Constraints ---")
    parent_min, parent_max = Ints('parent_min parent_max')
    child_min, child_max = Ints('child_min child_max')
    v = Int('v')
    
    # Range -> Range
    # Parent subsumes child if child's bounds are entirely within parent's bounds
    hyp_range = And(child_min >= parent_min, child_max <= parent_max)
    # If a value satisfies child, it must satisfy parent
    conc_range = ForAll([v], Implies(And(v >= child_min, v <= child_max), 
                                     And(v >= parent_min, v <= parent_max)))
    prove_theorem("Range Subsumes Range", hyp_range, conc_range)
    
    # Range -> Exact
    # Parent subsumes child exact if exact value is within parent's bounds
    hyp_exact = And(v >= parent_min, v <= parent_max)
    conc_exact = Implies(v == v, And(v >= parent_min, v <= parent_max)) # Trivial, but formalizes the rule
    prove_theorem("Range Subsumes Exact", hyp_exact, conc_exact)


def run_cidr_proofs():
    print("\n--- CIDR Constraints ---")
    # Using 32-bit vectors to represent IP networks and masks
    parent_net, parent_mask = BitVecs('parent_net parent_mask', 32)
    child_net, child_mask = BitVecs('child_net child_mask', 32)
    ip = BitVec('ip', 32)
    
    # A valid CIDR mask has contiguous 1s from the MSB, but for subsumption
    # the generic rule is: child_mask must be at least as strict as parent_mask
    # and the child_net strictly falls under parent_net's mask.
    # Note: in real IP networking, mask arithmetic works exactly like this.
    hyp_cidr = And(
        # The child's network bits (as masked by the parent's wider mask) must match 
        # the parent's network bits exactly.
        (child_net & parent_mask) == (parent_net & parent_mask),
        # And the child's mask must contain all the bits of the parent's mask
        (child_mask & parent_mask) == parent_mask
    )
    
    child_accepts = (ip & child_mask) == (child_net & child_mask)
    parent_accepts = (ip & parent_mask) == (parent_net & parent_mask)
    
    conc_cidr = ForAll([ip], Implies(child_accepts, parent_accepts))
    prove_theorem("CIDR Subsumes CIDR", hyp_cidr, conc_cidr)


def run_cel_proofs():
    print("\n--- CEL Constraints ---")
    # Tenuo's CEL attenuation strictly enforces conjunction (ANDing the child expression to the parent)
    parent_expr = Bool('parent_expr')
    child_expr = Bool('child_expr') # representing the additional restriction
    
    # The child's effective logic is parent && child
    effective_child = And(parent_expr, child_expr)
    
    # Does the effective child imply the parent? (Monotonicity)
    hyp_cel = True
    conc_cel = Implies(effective_child, parent_expr)
    prove_theorem("CEL Conjunction is Monotonic", hyp_cel, conc_cel)


def run_url_proofs():
    print("\n--- URL Pattern Constraints ---")
    # URL modelling: checking domain suffixes, paths prefixes
    v_domain, v_path = Strings('v_domain v_path')
    parent_dom_suffix, parent_path_prefix = Strings('parent_dom_suffix parent_path_prefix')
    child_dom_suffix, child_path_prefix = Strings('child_dom_suffix child_path_prefix')
    
    # Hypothesis: child domain suffix is a narrower/equal subdomain AND child path is a longer/equal subpath
    hyp_url = And(
        SuffixOf(parent_dom_suffix, child_dom_suffix),
        PrefixOf(parent_path_prefix, child_path_prefix)
    )
    
    child_accepts = And(
        SuffixOf(child_dom_suffix, v_domain),
        PrefixOf(child_path_prefix, v_path)
    )
    
    parent_accepts = And(
        SuffixOf(parent_dom_suffix, v_domain),
        PrefixOf(parent_path_prefix, v_path)
    )
    
    conc_url = ForAll([v_domain, v_path], Implies(child_accepts, parent_accepts))
    prove_theorem("UrlPattern Subsumes UrlPattern", hyp_url, conc_url)

if __name__ == '__main__':
    run_range_proofs()
    run_cidr_proofs()
    run_cel_proofs()
    run_url_proofs()
