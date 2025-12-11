#!/usr/bin/env python3
"""
Tenuo + LangGraph: SecureGraph Example

This example demonstrates how to use SecureGraph to automatically manage
and attenuate warrants in a multi-agent system.
"""

from typing import TypedDict, Optional, Literal
from langgraph.graph import StateGraph, END, START
from tenuo import Warrant, Keypair, Pattern, AuthorizationError
from tenuo.langgraph import SecureGraph
import os

# =============================================================================
# 1. Define State (Standard LangGraph)
# =============================================================================

class AgentState(TypedDict):
    input: str
    project_id: str # Added for interpolation demo
    research: Optional[str]
    output: Optional[str]
    # Tenuo fields are injected automatically by SecureGraph

# =============================================================================
# 2. Define Tools (Protected)
# =============================================================================

# In a real app, these would be complex tools.
# Here we simulate them to show authorization checks.

# =============================================================================
# 2. Define Tools (Plain Functions)
# =============================================================================

# In a real app, these would be complex tools.
# Here we simulate them to show authorization checks.

def _search_tool(query: str, file_path: str = "/tmp/research/dummy") -> str:
    print(f"   [TOOL] search('{query}') authorized!")
    return "Search results for: " + query

def _read_file_tool(file_path: str) -> str:
    print(f"   [TOOL] read_file('{file_path}') authorized!")
    return f"Content of {file_path}"

def _write_file_tool(file_path: str, content: str) -> str:
    print(f"   [TOOL] write_file('{file_path}') authorized!")
    return f"Wrote to {file_path}"

# Protect tools (Auto-Instrumentation)
# This wraps them to check the warrant in the current context
from tenuo.langgraph import protect_tool

search_tool = protect_tool(
    _search_tool, 
    name="search",
    extract_args=lambda query, file_path="/tmp/research/dummy", **kwargs: {"query": query, "file_path": file_path}
)

read_file_tool = protect_tool(
    _read_file_tool, 
    name="read_file",
    extract_args=lambda file_path, **kwargs: {"file_path": file_path}
)

write_file_tool = protect_tool(
    _write_file_tool, 
    name="write_file",
    extract_args=lambda file_path, content, **kwargs: {"file_path": file_path}
)

# =============================================================================
# 3. Define Nodes (Standard LangGraph)
# =============================================================================

def supervisor(state: AgentState) -> dict:
    print("\n[NODE] Supervisor")
    # Simple logic: if no research, delegate to researcher.
    # If research done but no output, delegate to writer.
    return {}

def researcher(state: AgentState) -> dict:
    print("\n[NODE] Researcher")
    try:
        # Try authorized tools
        # Must pass valid file_path to satisfy project constraint
        search_tool("Q3 results", file_path=f"/tmp/{state['project_id']}/dummy")
        # Access project-specific file (interpolated warrant should allow this)
        read_file_tool(f"/tmp/{state['project_id']}/data.txt")
        
        # Try UNAUTHORIZED tool (should fail)
        print("   [TEST] Trying unauthorized tool (write_file)...")
        try:
            write_file_tool("/tmp/output/report.txt", "data")
        except AuthorizationError:
            print("   [PASS] write_file blocked correctly!")
            
        # Try UNAUTHORIZED path (should fail)
        print("   [TEST] Trying unauthorized path (/etc/passwd)...")
        try:
            read_file_tool("/etc/passwd")
        except AuthorizationError:
            print("   [PASS] read_file(/etc/passwd) blocked correctly!")

        return {"research": "Q3 Revenue: $10M"}
    except Exception as e:
        print(f"   [ERROR] {e}")
        return {"research": "Error"}

def writer(state: AgentState) -> dict:
    print("\n[NODE] Writer")
    try:
        # Try authorized tool
        write_file_tool("/tmp/output/report.txt", f"Report: {state['research']}")
        
        # Try UNAUTHORIZED tool (should fail)
        print("   [TEST] Trying unauthorized tool (search)...")
        try:
            search_tool("something")
        except AuthorizationError:
            print("   [PASS] search blocked correctly!")
            
        return {"output": "Report generated"}
    except Exception as e:
        print(f"   [ERROR] {e}")
        return {"output": "Error"}

def route(state: AgentState) -> Literal["researcher", "writer", END]:
    if not state.get("research"):
        return "researcher"
    if not state.get("output"):
        return "writer"
    return END

# =============================================================================
# 4. Build Graph & Secure It
# =============================================================================

def main():
    # Build standard graph
    graph = StateGraph(AgentState)
    graph.add_node("supervisor", supervisor)
    graph.add_node("researcher", researcher)
    graph.add_node("writer", writer)
    
    graph.set_entry_point("supervisor")
    graph.add_conditional_edges("supervisor", route)
    graph.add_edge("researcher", "supervisor")
    graph.add_edge("writer", END)
    
    # Create Root Warrant
    # Root allows EVERYTHING under /tmp
    kp = Keypair.generate()
    root_warrant = Warrant.create(
        tool="*", 
        constraints={"file_path": Pattern("/tmp/**")},
        ttl_seconds=3600,
        keypair=kp,
        authorized_holder=kp.public_key()
    )
    
    # Define Dynamic Config with Interpolation
    dynamic_config = {
        "settings": {"allow_unlisted_nodes": False},
        "nodes": {
            "supervisor": {"role": "supervisor"},
            "researcher": {
                "attenuate": {
                    "tools": ["search", "read_file"],
                    "constraints": {
                        # Dynamic constraint based on project_id in state
                        "file_path": {"pattern": "/tmp/${state.project_id}/*"}
                    }
                }
            },
            "writer": {
                "attenuate": {
                    "tools": ["write_file"],
                    "constraints": {
                        "file_path": {"pattern": "/tmp/output/*"}
                    }
                }
            }
        }
    }
    
    # Wrap with SecureGraph
    print("=== Tenuo SecureGraph Demo ===")
    print("Initializing SecureGraph with dynamic config...")
    
    secure = SecureGraph(
        graph=graph,
        config=dynamic_config,
        root_warrant=root_warrant,
        keypair=kp
    )
    
    # Run with project_id in state
    print("\nStarting Execution (Project: alpha)...")
    result = secure.invoke({
        "input": "Generate Q3 Report",
        "project_id": "alpha" # This will be interpolated into the warrant
    })
    
    print("\n=== Final Result ===")
    print(result)

if __name__ == "__main__":
    main()
