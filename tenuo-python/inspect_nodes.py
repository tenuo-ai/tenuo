from langgraph.graph import StateGraph
from typing import TypedDict

class S(TypedDict):
    pass

def node(state): return {}

g = StateGraph(S)
g.add_node("test", node)

g.add_conditional_edges("test", lambda x: "end")

print(f"Edges: {g.edges}")
print(f"Branches: {g.branches}")
