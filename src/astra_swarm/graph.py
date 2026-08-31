from typing import Required, TypedDict, cast

from langgraph.graph import END, START, StateGraph

from .react_agent import AgentInvestigation, react_triage
from .router import RoutingDecision, classify_alert


class TriageState(TypedDict, total=False):
    raw: Required[str]
    routing: RoutingDecision
    investigation: AgentInvestigation


def router_node(state: TriageState) -> dict:
    return {"routing": classify_alert(state["raw"])}


def agent_node(state: TriageState) -> dict:
    assert "routing" in state, "agent_node requires router_node to have run first"
    return {"investigation": react_triage(state["raw"], state["routing"])}


def build_triage_graph():
    builder = StateGraph(TriageState)
    builder.add_node("router", router_node)
    builder.add_node("agent", agent_node)
    builder.add_edge(START, "router")
    builder.add_edge("router", "agent")
    builder.add_edge("agent", END)
    return builder.compile()


triage_graph = build_triage_graph()


def graph_triage(raw_alert: str) -> TriageState:
    return cast(TriageState, triage_graph.invoke({"raw": raw_alert}))
