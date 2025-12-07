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
    
    # ========================================================================
    # STEP 1: Create Warrant (SIMULATION - In production, from control plane)
    # ========================================================================
    try:
        # SIMULATION: Generate keypair for demo
        # In production: Control plane keypair is loaded from secure storage
        keypair = Keypair.generate()
        
        # SIMULATION: Create warrant with hardcoded constraints
        # HARDCODED: Pattern("staging-*"), Range.max_value(10000.0), ttl_seconds=3600
        # In production: Constraints come from policy engine or configuration
        warrant = Warrant.create(
            tool="upgrade_cluster",  # Note: functions can use different tools
            constraints={
                "cluster": Pattern("staging-*"),  # HARDCODED: Only staging clusters for demo
                "budget": Range.max_value(10000.0)  # HARDCODED: $10k max budget for demo
            },
            ttl_seconds=3600,  # HARDCODED: 1 hour TTL. In production, use env var or config.
            keypair=keypair
        )
    except Exception as e:
        print(f"✗ Error creating warrant: {e}")
        return
    
    # ========================================================================
    # PATTERN 1: Set Warrant in Context (REAL CODE - Production-ready)
    # ========================================================================
    print("1. Setting warrant in context and processing request...")
    try:
        with set_warrant_context(warrant):
            # All @lockdown functions in this context will use the warrant
            # HARDCODED VALUES: cluster="staging-web", budget=5000.0, action="restart"
            # In production: These come from request parameters
            process_request(
                cluster="staging-web",
                budget=5000.0,
                action="restart"
            )
    except AuthorizationError as e:
        print(f"   ✗ Authorization failed: {e}\n")
    except Exception as e:
        print(f"   ✗ Unexpected error: {e}\n")
    
    # ========================================================================
    # PATTERN 2: FastAPI Middleware Example (SIMULATION)
    # ========================================================================
    print("2. [SIMULATION] Simulating FastAPI middleware pattern...")
    def fastapi_middleware_example(request_warrant: Warrant):
        """
        [SIMULATION] Simulates FastAPI middleware that sets warrant in context.
        
        In production, this would be actual FastAPI middleware:
            @app.middleware("http")
            async def tenuo_middleware(request: Request, call_next):
                warrant = load_warrant_from_header(request.headers)
                with set_warrant_context(warrant):
                    return await call_next(request)
        """
        try:
            with set_warrant_context(request_warrant):
                # Process the request - all protected functions use context warrant
                # HARDCODED VALUES: cluster="staging-web", budget=3000.0
                upgrade_cluster(cluster="staging-web", budget=3000.0)
                print("   ✓ FastAPI request processed\n")
        except AuthorizationError as e:
            print(f"   ✗ Authorization failed: {e}\n")
        except Exception as e:
            print(f"   ✗ Unexpected error: {e}\n")
    
    try:
        fastapi_middleware_example(warrant)
    except Exception as e:
        print(f"   ✗ Error in middleware example: {e}\n")
    
    # ========================================================================
    # PATTERN 3: Error When No Warrant in Context (REAL CODE - Production-ready)
    # ========================================================================
    print("3. Testing error when no warrant in context...")
    try:
        # Call without setting context - should raise AuthorizationError
        # HARDCODED VALUES: cluster="staging-web", budget=5000.0
        upgrade_cluster(cluster="staging-web", budget=5000.0)
        print("   ✗ Should have raised AuthorizationError!\n")
    except AuthorizationError as e:
        print(f"   ✓ Correctly raised: {str(e)[:60]}...\n")
    except Exception as e:
        print(f"   ✗ Unexpected error (not AuthorizationError): {e}\n")
    
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

