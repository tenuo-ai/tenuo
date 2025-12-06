#!/usr/bin/env python3
"""
Example demonstrating the ContextVar pattern for LangChain/FastAPI integration.

This pattern allows warrants to be set at the request/message level and
automatically used by all @lockdown-decorated functions in the call stack.
"""

from tenuo import (
    Keypair, Warrant, Pattern, Range,
    lockdown, set_warrant_context, AuthorizationError
)


# Functions decorated without explicit warrant - they'll use context
@lockdown(tool="upgrade_cluster")
def upgrade_cluster(cluster: str, budget: float):
    """This function uses the warrant from context."""
    print(f"✓ Upgrading cluster {cluster} with budget ${budget}")
    # ... actual upgrade logic here


@lockdown(tool="manage_infrastructure")
def manage_infrastructure(cluster: str, action: str):
    """Another function that uses context warrant."""
    print(f"✓ Managing {cluster}: {action}")
    # ... actual management logic here


def process_request(cluster: str, budget: float, action: str):
    """
    Simulates a request handler that calls multiple protected functions.
    The warrant is set once at the top level and used by all functions.
    """
    print(f"Processing request for {cluster}...")
    
    # All these calls will use the warrant from context
    upgrade_cluster(cluster=cluster, budget=budget)
    manage_infrastructure(cluster=cluster, action=action)
    
    print("Request processed successfully\n")


def main():
    print("=== Tenuo ContextVar Pattern (LangChain/FastAPI) ===\n")
    
    # Create a warrant
    keypair = Keypair.generate()
    warrant = Warrant.create(
        tool="upgrade_cluster",  # Note: functions can use different tools
        constraints={
            "cluster": Pattern("staging-*"),
            "budget": Range.max_value(10000.0)
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    # Pattern 1: Set warrant in context and process request
    print("1. Setting warrant in context and processing request...")
    try:
        with set_warrant_context(warrant):
            # All @lockdown functions in this context will use the warrant
            process_request(
                cluster="staging-web",
                budget=5000.0,
                action="restart"
            )
    except AuthorizationError as e:
        print(f"   ✗ Authorization failed: {e}\n")
    
    # Pattern 2: FastAPI middleware example (simulated)
    print("2. Simulating FastAPI middleware pattern...")
    def fastapi_middleware_example(request_warrant: Warrant):
        """Simulates FastAPI middleware that sets warrant in context."""
        with set_warrant_context(request_warrant):
            # Process the request - all protected functions use context warrant
            upgrade_cluster(cluster="staging-web", budget=3000.0)
            print("   ✓ FastAPI request processed\n")
    
    fastapi_middleware_example(warrant)
    
    # Pattern 3: Error when no warrant in context
    print("3. Testing error when no warrant in context...")
    try:
        # Call without setting context
        upgrade_cluster(cluster="staging-web", budget=5000.0)
        print("   ✗ Should have raised AuthorizationError!\n")
    except AuthorizationError as e:
        print(f"   ✓ Correctly raised: {e}\n")
    
    # Pattern 4: Nested contexts (context inheritance)
    print("4. Testing nested contexts...")
    warrant1 = Warrant.create(
        tool="upgrade_cluster",
        constraints={"cluster": Pattern("staging-*")},
        ttl_seconds=3600,
        keypair=keypair
    )
    warrant2 = Warrant.create(
        tool="upgrade_cluster",
        constraints={"cluster": Pattern("production-*")},
        ttl_seconds=3600,
        keypair=keypair
    )
    
    with set_warrant_context(warrant1):
        print("   Outer context: staging-*")
        upgrade_cluster(cluster="staging-web", budget=5000.0)
        
        with set_warrant_context(warrant2):
            print("   Inner context: production-*")
            try:
                upgrade_cluster(cluster="production-web", budget=5000.0)
                print("   ✓ Inner context works\n")
            except AuthorizationError as e:
                print(f"   ✗ {e}\n")
        
        # Back to outer context
        print("   Back to outer context: staging-*")
        upgrade_cluster(cluster="staging-web", budget=5000.0)
    
    print("=== Context pattern example completed! ===")
    print("\nThis pattern is ideal for:")
    print("  - FastAPI: Set warrant in middleware, use in route handlers")
    print("  - LangChain: Set warrant in callback, use in tool functions")
    print("  - Async frameworks: Context propagates through await boundaries")


if __name__ == "__main__":
    main()

