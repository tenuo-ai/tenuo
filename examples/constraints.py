#!/usr/bin/env python3
"""
Tenuo Constraints Example

This example demonstrates all constraint types available in Tenuo:
- Pattern: Glob-style pattern matching (e.g., "staging-*", "/tmp/*")
- Exact: Exact value matching
- Range: Numeric ranges (min, max, or both)
- OneOf: Value must be one of a set of allowed values
- CEL: Common Expression Language for complex constraints

Requirements:
    pip install tenuo

Run:
    python examples/constraints.py
"""

from tenuo import Keypair, Warrant, Pattern, Exact, Range, OneOf, CEL, AuthorizationError

def main():
    print("=" * 70)
    print("Tenuo Constraints Example")
    print("=" * 70)
    print()
    
    # Generate a keypair for signing warrants
    keypair = Keypair.generate()
    
    # ============================================================================
    # 1. Pattern Constraints (Glob-style matching)
    # ============================================================================
    print("1. Pattern Constraints (Glob-style matching)")
    print("-" * 70)
    print("Pattern constraints use glob-style matching:")
    print("  - '*' matches any sequence of characters")
    print("  - '?' matches a single character")
    print("  - Useful for: cluster names, file paths, resource IDs")
    print()
    
    pattern_warrant = Warrant.create(
        tool="manage_cluster",
        constraints={
            "cluster": Pattern("staging-*"),  # Matches staging-web, staging-db, etc.
            "region": Pattern("us-*"),        # Matches us-east, us-west, etc.
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    # Test pattern matching
    test_cases = [
        ("staging-web", "us-east", True, "Matches both patterns"),
        ("staging-db", "us-west", True, "Matches both patterns"),
        ("production-web", "us-east", False, "Cluster doesn't match 'staging-*'"),
        ("staging-web", "eu-west", False, "Region doesn't match 'us-*'"),
    ]
    
    for cluster, region, expected, reason in test_cases:
        result = pattern_warrant.authorize(
            tool="manage_cluster",
            args={"cluster": cluster, "region": region}
        )
        status = "✓" if result == expected else "✗"
        print(f"  {status} cluster={cluster}, region={region}: {result} ({reason})")
    print()
    
    # ============================================================================
    # 2. Exact Constraints (Exact value matching)
    # ============================================================================
    print("2. Exact Constraints (Exact value matching)")
    print("-" * 70)
    print("Exact constraints require an exact match:")
    print("  - Useful for: specific IDs, enum values, fixed configurations")
    print()
    
    exact_warrant = Warrant.create(
        tool="delete_database",
        constraints={
            "db_name": Exact("test-db"),      # Must be exactly "test-db"
            "environment": Exact("staging"),   # Must be exactly "staging"
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    test_cases = [
        ("test-db", "staging", True, "Exact match"),
        ("test-db", "production", False, "Environment mismatch"),
        ("prod-db", "staging", False, "Database name mismatch"),
        ("test-db-backup", "staging", False, "Database name not exact"),
    ]
    
    for db_name, env, expected, reason in test_cases:
        result = exact_warrant.authorize(
            tool="delete_database",
            args={"db_name": db_name, "environment": env}
        )
        status = "✓" if result == expected else "✗"
        print(f"  {status} db_name={db_name}, environment={env}: {result} ({reason})")
    print()
    
    # ============================================================================
    # 3. Range Constraints (Numeric ranges)
    # ============================================================================
    print("3. Range Constraints (Numeric ranges)")
    print("-" * 70)
    print("Range constraints limit numeric values:")
    print("  - Range.min_value(x): value >= x")
    print("  - Range.max_value(x): value <= x")
    print("  - Range.between(min, max): min <= value <= max")
    print("  - Useful for: budgets, quotas, resource limits")
    print()
    
    range_warrant = Warrant.create(
        tool="allocate_resources",
        constraints={
            "budget": Range.max_value(1000.0),           # Budget <= $1000
            "cpu_cores": Range.between(1, 8),           # 1 <= CPU cores <= 8
            "memory_gb": Range.min_value(2.0),          # Memory >= 2GB
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    test_cases = [
        (500.0, 4, 4.0, True, "All within ranges"),
        (1500.0, 4, 4.0, False, "Budget exceeds max"),
        (500.0, 10, 4.0, False, "CPU cores exceed max"),
        (500.0, 4, 1.0, False, "Memory below min"),
        (1000.0, 8, 2.0, True, "At boundaries (inclusive)"),
    ]
    
    for budget, cpu, memory, expected, reason in test_cases:
        result = range_warrant.authorize(
            tool="allocate_resources",
            args={"budget": budget, "cpu_cores": cpu, "memory_gb": memory}
        )
        status = "✓" if result == expected else "✗"
        print(f"  {status} budget=${budget}, cpu={cpu}, memory={memory}GB: {result} ({reason})")
    print()
    
    # ============================================================================
    # 4. OneOf Constraints (Value must be in a set)
    # ============================================================================
    print("4. OneOf Constraints (Value must be in allowed set)")
    print("-" * 70)
    print("OneOf constraints allow a value to be one of several options:")
    print("  - Useful for: allowed actions, whitelisted values, enum-like choices")
    print()
    
    oneof_warrant = Warrant.create(
        tool="execute_action",
        constraints={
            "action": OneOf(["restart", "stop", "start"]),  # Must be one of these
            "service": OneOf(["web", "api", "worker"]),     # Must be one of these
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    test_cases = [
        ("restart", "web", True, "Both values in allowed sets"),
        ("stop", "api", True, "Both values in allowed sets"),
        ("delete", "web", False, "Action not in allowed set"),
        ("restart", "database", False, "Service not in allowed set"),
    ]
    
    for action, service, expected, reason in test_cases:
        result = oneof_warrant.authorize(
            tool="execute_action",
            args={"action": action, "service": service}
        )
        status = "✓" if result == expected else "✗"
        print(f"  {status} action={action}, service={service}: {result} ({reason})")
    print()
    
    # ============================================================================
    # 5. CEL Constraints (Common Expression Language)
    # ============================================================================
    print("5. CEL Constraints (Common Expression Language)")
    print("-" * 70)
    print("CEL constraints allow complex boolean expressions:")
    print("  - Supports: comparisons, logical operators, string functions")
    print("  - Useful for: complex business logic, multi-field validation")
    print("  - Example: 'cluster.startsWith(\"staging\") && budget <= 1000'")
    print()
    
    cel_warrant = Warrant.create(
        tool="deploy_service",
        constraints={
            # CEL expression: cluster must start with "staging" AND budget <= 1000
            # Note: CEL expressions reference the field name directly
            "cluster": CEL('cluster.startsWith("staging") && cluster.size() < 20'),
            "budget": CEL('budget <= 1000.0 && budget > 0'),
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    test_cases = [
        ("staging-web", 500.0, True, "Matches CEL expressions"),
        ("staging-db", 1500.0, False, "Budget exceeds CEL limit"),
        ("production-web", 500.0, False, "Cluster doesn't start with 'staging'"),
        ("staging-very-long-cluster-name", 500.0, False, "Cluster name too long"),
    ]
    
    for cluster, budget, expected, reason in test_cases:
        result = cel_warrant.authorize(
            tool="deploy_service",
            args={"cluster": cluster, "budget": budget}
        )
        status = "✓" if result == expected else "✗"
        print(f"  {status} cluster={cluster}, budget=${budget}: {result} ({reason})")
    print()
    
    # ============================================================================
    # 6. Mixed Constraints (Combining different types)
    # ============================================================================
    print("6. Mixed Constraints (Combining different constraint types)")
    print("-" * 70)
    print("You can combine different constraint types in a single warrant:")
    print("  - Each constraint is evaluated independently")
    print("  - ALL constraints must be satisfied for authorization to succeed")
    print()
    
    mixed_warrant = Warrant.create(
        tool="manage_infrastructure",
        constraints={
            "cluster": Pattern("staging-*"),                    # Pattern matching
            "environment": Exact("staging"),                   # Exact match
            "budget": Range.max_value(5000.0),                 # Range constraint
            "action": OneOf(["scale", "restart", "update"]),   # OneOf constraint
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    test_cases = [
        ("staging-web", "staging", 3000.0, "scale", True, "All constraints satisfied"),
        ("staging-web", "production", 3000.0, "scale", False, "Environment mismatch"),
        ("staging-web", "staging", 6000.0, "scale", False, "Budget exceeds limit"),
        ("staging-web", "staging", 3000.0, "delete", False, "Action not in allowed set"),
        ("production-web", "staging", 3000.0, "scale", False, "Cluster pattern mismatch"),
    ]
    
    for cluster, env, budget, action, expected, reason in test_cases:
        result = mixed_warrant.authorize(
            tool="manage_infrastructure",
            args={"cluster": cluster, "environment": env, "budget": budget, "action": action}
        )
        status = "✓" if result == expected else "✗"
        print(f"  {status} cluster={cluster}, env={env}, budget=${budget}, action={action}: {result}")
        print(f"      ({reason})")
    print()
    
    # ============================================================================
    # 7. Constraint Attenuation (Delegation with narrower constraints)
    # ============================================================================
    print("7. Constraint Attenuation (Delegation with narrower constraints)")
    print("-" * 70)
    print("When delegating warrants, constraints can only become MORE restrictive:")
    print("  - Pattern can become Exact or narrower Pattern")
    print("  - Range can only shrink (max decreases, min increases)")
    print("  - OneOf can only have fewer options")
    print("  - This ensures capabilities only shrink, never expand")
    print()
    
    # Create a root warrant with broad constraints
    root_warrant = Warrant.create(
        tool="manage_infrastructure",
        constraints={
            "cluster": Pattern("staging-*"),      # Broad: any staging cluster
            "budget": Range.max_value(10000.0),   # Broad: up to $10k
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    # Create a worker keypair
    worker_keypair = Keypair.generate()
    
    # Attenuate to narrower constraints
    worker_warrant = root_warrant.attenuate(
        constraints={
            "cluster": Exact("staging-web"),      # Narrower: only staging-web
            "budget": Range.max_value(1000.0),    # Narrower: only up to $1k
        },
        keypair=worker_keypair
    )
    
    print("  Root warrant constraints:")
    print(f"    - cluster: Pattern('staging-*')")
    print(f"    - budget: Range.max_value(10000.0)")
    print()
    print("  Worker warrant constraints (attenuated):")
    print(f"    - cluster: Exact('staging-web')")
    print(f"    - budget: Range.max_value(1000.0)")
    print()
    
    # Test that worker warrant is more restrictive
    test_cases = [
        ("staging-web", 500.0, True, "Worker can access staging-web with $500"),
        ("staging-db", 500.0, False, "Worker cannot access staging-db (not exact match)"),
        ("staging-web", 2000.0, False, "Worker cannot exceed $1k budget"),
    ]
    
    for cluster, budget, expected, reason in test_cases:
        result = worker_warrant.authorize(
            tool="manage_infrastructure",
            args={"cluster": cluster, "budget": budget}
        )
        status = "✓" if result == expected else "✗"
        print(f"  {status} cluster={cluster}, budget=${budget}: {result} ({reason})")
    print()
    
    print("=" * 70)
    print("Constraints Example Complete!")
    print("=" * 70)
    print()
    print("Key Takeaways:")
    print("  1. Pattern: Use for glob-style matching (clusters, paths, IDs)")
    print("  2. Exact: Use for specific values that must match exactly")
    print("  3. Range: Use for numeric limits (budgets, quotas, resources)")
    print("  4. OneOf: Use for whitelisted sets of allowed values")
    print("  5. CEL: Use for complex boolean expressions")
    print("  6. Mix: Combine different types for fine-grained control")
    print("  7. Attenuate: Constraints can only become more restrictive when delegating")
    print()


if __name__ == "__main__":
    main()

