from typing import Required, TypedDict, cast

from langgraph.graph import END, START, StateGraph

from pydantic import BaseModel, Field, field_validator

from .alerts import _ask_structured
from .react_agent import AgentInvestigation, react_triage
from .router import RoutingDecision, classify_alert


class InvestigationEvaluation(BaseModel):
    """Score an AgentInvestigation against triage-quality criteria."""

    completeness: float = Field(description="0.0-1.0: covers the alert's key aspects")
    citation_quality: float = Field(description="0.0-1.0: ATT&CK techniques justified")
    severity_defensibility: float = Field(
        description="0.0-1.0: severity backed by evidence"
    )
    overall_pass: bool = Field(description="True iff all three above >= 0.7")
    feedback: str = Field(description="One paragraph on what to improve if not passing")

    @field_validator("completeness", "citation_quality", "severity_defensibility")
    @classmethod
    def _bounded(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"score out of range: {v}")
        return v


class TriageState(TypedDict, total=False):
    raw: Required[str]
    routing: RoutingDecision
    investigation: AgentInvestigation
    evaluation: InvestigationEvaluation
    refinement_count: int


def router_node(state: TriageState) -> dict:
    return {"routing": classify_alert(state["raw"])}


def agent_node(state: TriageState) -> dict:
    assert "routing" in state, "agent_node requires router_node to have run first"
    return {"investigation": react_triage(state["raw"], state["routing"])}


def evaluator_node(state: TriageState) -> dict:
    """Score the current investigation. Never modifies the investigation itself."""
    assert (
        "investigation" in state
    ), "evaluator_node requires agent_node to have run first"
    assert "routing" in state, "evaluator_node requires agent_node to have run first"
    inv = state["investigation"]
    prompt = f"""You are a senior SOC lead reviewing a junior analyst's triage.
Score the investigation below on three criteria (0.0-1.0 each) and decide whether
it passes review (all three >= 0.7). If not, give one paragraph of specific feedback.

Alert: {state['raw']}
Routing: {state['routing'].alert_class.value} ({state['routing'].rationale})

Investigation:
- ATT&CK techniques cited: {[t.id + ' ' + t.name for t in inv.attack_techniques]}
- Identity signals: {inv.identity_signals}
- Key findings: {inv.key_findings}
- Severity: {inv.severity.value} — {inv.severity_rationale}
- Recommended response: {inv.recommended_response}
"""
    return {
        "evaluation": _ask_structured(prompt, InvestigationEvaluation, max_tokens=500)
    }


def refinement_router(state: TriageState) -> str:
    """Conditional edge — loop back to the agent, or end."""
    assert (
        "evaluation" in state
    ), "refinement_router requires evaluator_node to have run first"
    if state["evaluation"].overall_pass:
        return "end"
    if state.get("refinement_count", 0) >= 1:  # cap at 1 refinement
        return "end"
    return "refine"


def increment_refinement_node(state: TriageState) -> dict:
    """Small housekeeping node — bumps the loop counter before re-running the agent."""
    return {"refinement_count": state.get("refinement_count", 0) + 1}


def build_triage_graph():
    """Includes the evaluator + refinement loop."""
    builder = StateGraph(TriageState)
    builder.add_node("router", router_node)
    builder.add_node("agent", agent_node)
    builder.add_node("evaluator", evaluator_node)
    builder.add_node("increment_refinement", increment_refinement_node)

    builder.add_edge(START, "router")
    builder.add_edge("router", "agent")
    builder.add_edge("agent", "evaluator")
    builder.add_conditional_edges(
        "evaluator",
        refinement_router,
        {"refine": "increment_refinement", "end": END},
    )
    builder.add_edge("increment_refinement", "agent")
    return builder.compile()


triage_graph = build_triage_graph()


def graph_triage(raw_alert: str) -> TriageState:
    return cast(TriageState, triage_graph.invoke({"raw": raw_alert}))
