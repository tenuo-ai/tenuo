"""
Example: Protecting Third-Party Tools with protect_tools

This example demonstrates how to use `protect_tools` to secure tools that you
don't own (e.g., from langchain_community) and therefore cannot decorate with @lockdown.

Scenario:
    We have a "third-party" search tool that we want to use in our agent.
    We wrap it with `protect_tools` to enforce warrant authorization.
"""

from typing import Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field
from tenuo import Keypair, Warrant, Pattern, set_warrant_context, set_keypair_context, AuthorizationError
from tenuo.langchain import protect_tools

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
keypair = Keypair.generate()

# Create a warrant that authorizes "search" but only for queries starting with "safe"
warrant = Warrant.issue(
    tool="search",
    constraints={
        "query": Pattern("safe*")  # Only allow safe queries
    },
    ttl_seconds=3600,
    keypair=keypair,
    holder=keypair.public_key()
)

# -----------------------------------------------------------------------------
# 3. Protect the Tool
# -----------------------------------------------------------------------------

# Instantiate the "third-party" tool
original_tool = ThirdPartySearchTool()

# Wrap it with Tenuo protection
# This applies @lockdown(tool="search") dynamically
protected_tools = protect_tools(
    tools=[original_tool],
    warrant=warrant,
    keypair=keypair
)
protected_search = protected_tools[0]

# -----------------------------------------------------------------------------
# 4. Execute
# -----------------------------------------------------------------------------

print(f"Original tool name: {original_tool.name}")
print(f"Protected tool name: {protected_search.name}")  # type: ignore
print("-" * 40)

# Set the warrant context
with set_warrant_context(warrant), set_keypair_context(keypair):
    try:
        # Allowed query
        print("Attempting: 'safe query'...")
        # protect_tools returns a callable function, not a BaseTool, so we call it directly
        result = protected_search(query="safe query")
        print(f"✅ Success: {result}")
    except AuthorizationError as e:
        print(f"❌ Failed: {e}")

    print("-" * 40)

    try:
        # Blocked query
        print("Attempting: 'unsafe query'...")
        result = protected_search(query="unsafe query")
        print(f"✅ Success: {result}")
    except AuthorizationError as e:
        print(f"❌ Blocked: {e}")
