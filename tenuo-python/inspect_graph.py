from langgraph.graph import StateGraph
from typing import TypedDict

class S(TypedDict):
    pass

g = StateGraph(S)
print([a for a in dir(g) if not a.startswith('_')])
