from operator import add
from typing import Annotated, Optional, Required, TypedDict, cast
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field, field_validator

from .alerts import _ask_structured
from .react_agent import AgentInvestigation, react_triage
from .router import RoutingDecision, classify_alert
from .schemas import AttackTechniqueCitation, IdentitySignals


class InvestigationEvaluation(BaseModel):
    """Score an AgentInvestigation against triage-quality criteria."""

    completeness: float = Field(description="0.0-1.0: covers the alert's key aspects")
    citation_quality: float = Field(description="0.0-1.0: ATT&CK techniques justified")
    severity_defensibility: float = Field(
        description="0.0-1.0: severity backed by evidence"
    )
    overall_pass: bool = Field(description="True if all three above >= 0.7")
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
    # Worker outputs (each populated by one worker):
    enrichment: list[AttackTechniqueCitation]
    identity: Optional[IdentitySignals]
    # Assessment worker consumes the above and produces the investigation.
    investigation: AgentInvestigation
    evaluation: InvestigationEvaluation
    refinement_count: int
    # Trace of which workers ran — accumulated via the `add` reducer
    workers_run: Annotated[list[str], add]


class EnrichmentResult(BaseModel):
    techniques: list[AttackTechniqueCitation]


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


def enrichment_worker(state: TriageState) -> dict:
    """Focused ATT&CK enrichment — no auth logs, no severity."""
    assert (
        "routing" in state
    ), "enrichment_worker requires router_node to have run first"
    prompt = f"""Identify up to 3 MITRE ATT&CK techniques for this alert. Cite each with ID, name, tactics, and a one-sentence why_relevant. 
    If no clear fit, return empty list.

    Alert (class={state['routing'].alert_class.value}): {state['raw']}"""
    # Reuse the run_with_tools_structured path but with a narrower schema
    from .agent_loop import run_with_tools_structured

    result = run_with_tools_structured(
        prompt,
        output_model=EnrichmentResult,
        max_rounds=6,
        max_tokens=1200,
    )
    return {"enrichment": result.techniques, "workers_run": ["enrichment"]}


def identity_worker(state: TriageState) -> dict:
    """Focused identity analysis via query_auth_logs — no ATT&CK, no severity."""
    assert "routing" in state, "identity_worker requires router_node to have run first"
    prompt = f"""Investigate identity signals for this alert. Use query_auth_logs for
any users mentioned (hours=336). Return an IdentitySignals object with the boolean
flags set based on the auth log patterns you find.

Alert: {state['raw']}
"""
    from .agent_loop import run_with_tools_structured

    result = run_with_tools_structured(
        prompt,
        output_model=IdentitySignals,
        max_rounds=6,
        max_tokens=1000,
    )
    return {"identity": result, "workers_run": ["identity"]}


def assessment_worker(state: TriageState) -> dict:
    """Synthesize enrichment + identity into an AgentInvestigation."""
    assert (
        "routing" in state
    ), "assessment_worker requires router_node to have run first"
    prompt = f"""Synthesize this triage evidence into a final assessment.

    Alert: {state['raw']}
    Routing: {state['routing'].alert_class.value}

    ATT&CK enrichment: {[t.model_dump() for t in state.get('enrichment', [])]}
    Identity signals: {state.get('identity')}

    Produce an AgentInvestigation with severity, rationale, confidence, and response. Set attack_techniques to the enrichment above, identity_signals to what identity found.
    """
    inv = _ask_structured(prompt, AgentInvestigation, max_tokens=1500)
    # Fill in the pieces the assessment prompt might have skipped
    inv = inv.model_copy(
        update={
            "attack_techniques": state.get("enrichment", []),
            "identity_signals": state.get("identity"),
        }
    )
    return {"investigation": inv, "workers_run": ["assessment"]}


# --- Orchestrator (conditional edge) ----------------------------------------


def orchestrator(state: TriageState) -> list[str]:
    """Pick which workers to fan out to, based on alert class.

    Returning a list of node names tells LangGraph to run them in parallel.
    """
    assert "routing" in state, "orchestrator requires router_node to have run first"
    cls = state["routing"].alert_class
    workers = ["enrichment"]  # always enrich
    if cls == "identity_auth":
        workers.append("identity")
    return workers


def build_triage_graph():
    """Includes the evaluator + refinement loop."""
    builder = StateGraph(TriageState)
    builder.add_node("router", router_node)
    builder.add_node("enrichment", enrichment_worker)
    builder.add_node("identity", identity_worker)
    builder.add_node("assessment", assessment_worker)
    builder.add_node("evaluator", evaluator_node)
    builder.add_node("increment_refinement", increment_refinement_node)

    builder.add_edge(START, "router")
    # Orchestrator: router fans out to N workers in parallel
    builder.add_conditional_edges("router", orchestrator, ["enrichment", "identity"])
    # Both workers converge to assessment
    builder.add_edge("enrichment", "assessment")
    builder.add_edge("identity", "assessment")
    # Assessment → evaluator → refine or end
    builder.add_edge("assessment", "evaluator")
    builder.add_conditional_edges(
        "evaluator",
        refinement_router,
        {"refine": "increment_refinement", "end": END},
    )
    # On refinement, redo assessment (not the enrichment/identity workers)
    builder.add_edge("increment_refinement", "assessment")
    return builder.compile()


triage_graph = build_triage_graph()


def graph_triage(raw_alert: str) -> TriageState:
    return cast(TriageState, triage_graph.invoke({"raw": raw_alert}))
