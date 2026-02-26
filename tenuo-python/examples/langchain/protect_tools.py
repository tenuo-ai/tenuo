"""
Example: Protecting Third-Party Tools with guard()

This example demonstrates how to use `guard()` to secure tools that you
don't own (e.g., from langchain_community) and therefore cannot decorate with @guard.
Solution: Use `tenuo.langchain.guard()` to wrap them at runtime.
Scenario:
    We have a "third-party" search tool that we want to use in our agent.
    We wrap it with `guard()` to enforce warrant authorization.
"""

from typing import Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from tenuo import Pattern, SigningKey, Warrant
from tenuo.exceptions import AuthorizationError
from tenuo.langchain import guard

# -----------------------------------------------------------------------------
# 1. Simulate a Third-Party Tool (e.g., from langchain_community)
# -----------------------------------------------------------------------------


class SearchInput(BaseModel):
    query: str = Field(description="The search query")


class ThirdPartySearchTool(BaseTool):
    """A simulated third-party search tool that we don't own."""

    name: str = "search"
    description: str = "Useful for searching the internet."
    args_schema: Type[BaseModel] = SearchInput

    def _run(self, query: str) -> str:
        # This is the "business logic" we can't modify
        return f"Results for: {query}"

    async def _arun(self, query: str) -> str:
        return f"Results for: {query}"


# -----------------------------------------------------------------------------
# 2. Setup Security (Keys & Warrants)
# -----------------------------------------------------------------------------

# Generate identity
keypair = SigningKey.generate()

# Create a warrant that authorizes "search" but only for queries starting with "safe"
warrant = (
    Warrant.mint_builder()
    .capability(
        "search",
        {
            "query": Pattern("safe*")  # Only allow safe queries
        },
    )
    .holder(keypair.public_key)
    .ttl(3600)
    .mint(keypair)
)

# -----------------------------------------------------------------------------
# 3. Protect the Tool
# -----------------------------------------------------------------------------

# Instantiate the "third-party" tool
original_tool = ThirdPartySearchTool()

# Wrap it with Tenuo protection using guard()
bound = warrant.bind(keypair)
protected_tools = guard([original_tool], bound)
protected_search = protected_tools[0]

# -----------------------------------------------------------------------------
# 4. Execute
# -----------------------------------------------------------------------------

print(f"Original tool name: {original_tool.name}")
print(f"Protected tool name: {protected_search.name}")
print("-" * 40)

try:
    # Allowed query
    print("Attempting: 'safe query'...")
    result = protected_search.invoke({"query": "safe query"})
    print(f"✅ Success: {result}")
except AuthorizationError as e:
    print(f"❌ Failed: {e}")

print("-" * 40)

try:
    # Blocked query
    print("Attempting: 'unsafe query'...")
    result = protected_search.invoke({"query": "unsafe query"})
    print(f"✅ Success: {result}")
except AuthorizationError as e:
    print(f"❌ Blocked: {e}")
