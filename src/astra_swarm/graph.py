from operator import add
from typing import Annotated, Iterator, Optional, Required, TypedDict, Literal, cast
import uuid
from langgraph.graph import END, START, StateGraph
from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field, field_validator

from astra_swarm.itdr import itdr_specialist_node

from .alerts import _ask_structured
from .react_agent import AgentInvestigation, react_triage
from .router import RoutingDecision, classify_alert
from .schemas import (
    AttackTechniqueCitation,
    ITDRFindings,
    IdentitySignals,
    ThreatIntelBrief,
)

# Renamed and versioned. Version field lets Week 5's eval harness detect
# whether a persisted incident was produced by an older graph.
STATE_VERSION = 4

# Register every custom class that appears in IncidentState so the checkpointer
# can round-trip them safely. New Pydantic/enum types added to state must be
# added here too — omitting one causes a warning now, an error in a future
# LangGraph release.
_ALLOWED_MODULES = [
    ("astra_swarm.router", "AlertClass"),
    ("astra_swarm.router", "RoutingDecision"),
    ("astra_swarm.schemas", "Severity"),
    ("astra_swarm.schemas", "AttackTechniqueCitation"),
    ("astra_swarm.schemas", "AgentInvestigation"),
    ("astra_swarm.schemas", "IdentitySignals"),
    ("astra_swarm.graph", "InvestigationEvaluation"),
    ("astra_swarm.graph", "ITDRFindings"),
    ("astra_swarm.graph", "ThreatIntelBrief"),
    ("astra_swarm.graph", "SupervisorDecision"),
]

setattr(JsonPlusSerializer, "allowed_msgpack_modules", tuple(_ALLOWED_MODULES))


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


class IncidentState(TypedDict, total=False):
    """Shared state for one incident's traversal through the supervisor graph.

    Version bumps with each schema evolution. Week 3 was implicitly v3
    (TriageState with workers_run accumulator). Week 4 = v4.
    """

    state_version: Required[int]  # always set — v4
    raw: Required[str]  # always set — input alert
    incident_id: Required[str]  # always set — unique per run

    # Router output
    routing: RoutingDecision

    # Worker outputs (each populated by one worker)
    enrichment: list[AttackTechniqueCitation]
    identity: Optional[ITDRFindings]  # Richer than plain IdentitySignals
    threat_intel: Optional[ThreatIntelBrief]  # SOC-analyst-style context

    # Assessment
    investigation: AgentInvestigation
    evaluation: InvestigationEvaluation
    refinement_count: int

    # Supervisor loop state
    supervisor_decisions: Annotated[list[dict], add]  # trace of every supervisor call
    supervisor_call_count: int  # cap loop
    workers_run: Annotated[list[str], add]  # accumulator preserved from Week 3

    # Escalation flag (set by conditional edge on high-severity)
    escalated: bool


class EnrichmentResult(BaseModel):
    techniques: list[AttackTechniqueCitation]


class SupervisorDecision(BaseModel):
    """The supervisor picks the next node to run, or END."""

    next_action: Literal[
        "call_soc_analyst",
        "call_itdr",
        "call_enrichment",
        "call_assessment",
        "done",
    ]
    rationale: str = Field(description="One sentence on why this is the next step")


SUPERVISOR_INSTRUCTIONS = """You are a senior SOC lead directing an investigation. After each
worker completes, you decide what happens next. Options:

- call_enrichment: get MITRE ATT&CK context for the alert
- call_itdr: run the identity-threat specialist (only useful if a user is involved)
- call_soc_analyst: get threat-intel / campaign context / kill-chain stage
- call_assessment: synthesize what's been gathered into a final verdict
- done: end the investigation (only if assessment is complete and passes evaluation)

Judgment principles:
- Always run enrichment early — ATT&CK context frames everything else.
- Run ITDR if the alert involves a specific user or authentication event.
- Run SOC analyst for suspected campaigns, unusual techniques, or lateral-movement patterns.
- Assessment must run at least once before done. If evaluation exists and failed, either call
  a worker to gather more evidence or call_assessment again to synthesize the current state.
- Prefer termination once you have enough evidence — do not add workers speculatively.
"""


def supervisor_node(state: IncidentState) -> dict:
    """Decide the next node to run based on current state."""
    assert "routing" in state, "supervisor_node requires router_node to have run first"
    # Cap the loop — never more than 8 supervisor calls per incident
    if state.get("supervisor_call_count", 0) >= 8:
        return {
            "supervisor_decisions": [
                {
                    "next_action": "done",
                    "rationale": "supervisor call cap reached — forcing termination",
                    "call_number": state.get("supervisor_call_count", 0) + 1,
                    "forced": True,
                }
            ],
            "supervisor_call_count": state.get("supervisor_call_count", 0) + 1,
        }

    evaluation = state.get("evaluation")
    evaluation_status = evaluation.overall_pass if evaluation else "not run"
    investigation = state.get("investigation")
    investigation_status = "complete" if investigation else "not run"

    prompt = f"""Current investigation state:

    Alert: {state["raw"][:400]}
    Routing: {state["routing"].alert_class.value} ({state["routing"].rationale})

    Workers run so far: {state.get("workers_run", [])}
    Enrichment: {len(state.get("enrichment", []))} techniques cited
    ITDR findings: {"populated" if state.get("identity") else "not run"}
    Threat intel: {"populated" if state.get("threat_intel") else "not run"}
    Assessment: {investigation_status}
    Evaluation: {evaluation_status}
    Refinements so far: {state.get("refinement_count", 0)}

    Supervisor call #{state.get("supervisor_call_count", 0) + 1} of 8.

    Decide the next action."""

    decision = _ask_structured(
        prompt,
        SupervisorDecision,
        system=SUPERVISOR_INSTRUCTIONS,
        max_tokens=300,
    )

    return {
        "supervisor_decisions": [
            {
                "next_action": decision.next_action,
                "rationale": decision.rationale,
                "call_number": state.get("supervisor_call_count", 0) + 1,
                "forced": False,
            }
        ],
        "supervisor_call_count": state.get("supervisor_call_count", 0) + 1,
    }


def soc_analyst_worker_node(state: IncidentState) -> dict:
    """Produce a ThreatIntelBrief — campaign context, kill-chain stage, prior context."""
    prompt = f"""You are a threat-intel analyst. Given this alert and the ATT&CK techniques
    already enriched, produce a ThreatIntelBrief with:
    - related_campaigns: known threat actors or campaigns matching this pattern (empty list if unclear)
    - kill_chain_stage: your best read (e.g. "initial access", "lateral movement", "exfiltration")
    - prior_alert_context: how you'd expect this to relate to a broader attack sequence
    - threat_severity_hint: your gut read as low/medium/high/critical

    Alert: {state["raw"]}
    Enriched techniques: {[t.model_dump() for t in state.get("enrichment", [])]}
    """
    brief = _ask_structured(prompt, ThreatIntelBrief, max_tokens=800)
    return {"threat_intel": brief, "workers_run": ["soc_analyst"]}


def supervisor_router(state: IncidentState) -> str:
    """Conditional edge — route to the node the supervisor named."""
    assert (
        "supervisor_decisions" in state
    ), "supervisor_router requires supervisor_node to have run first"
    last_decision = state["supervisor_decisions"][-1]
    action = last_decision["next_action"]
    return {
        "call_soc_analyst": "soc_analyst_worker",
        "call_itdr": "itdr_specialist",
        "call_enrichment": "enrichment_worker",
        "call_assessment": "assessment_worker",
        "done": "__end__",
    }[action]


def new_incident_state(raw_alert: str) -> IncidentState:
    """Build a fresh state with required fields populated."""
    return {
        "state_version": STATE_VERSION,
        "raw": raw_alert,
        "incident_id": f"INC-{uuid.uuid4().hex[:8]}",
        "supervisor_call_count": 0,
        "workers_run": [],
        "supervisor_decisions": [],
    }


def router_node(state: IncidentState) -> dict:
    return {"routing": classify_alert(state["raw"])}


def agent_node(state: IncidentState) -> dict:
    assert "routing" in state, "agent_node requires router_node to have run first"
    return {"investigation": react_triage(state["raw"], state["routing"])}


def evaluator_node(state: IncidentState) -> dict:
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


def refinement_router(state: IncidentState) -> str:
    """Conditional edge — loop back to the agent, or end."""
    assert (
        "evaluation" in state
    ), "refinement_router requires evaluator_node to have run first"
    if state["evaluation"].overall_pass:
        return "end"
    if state.get("refinement_count", 0) >= 1:  # cap at 1 refinement
        return "end"
    return "refine"


def increment_refinement_node(state: IncidentState) -> dict:
    """Small housekeeping node — bumps the loop counter before re-running the agent."""
    return {"refinement_count": state.get("refinement_count", 0) + 1}


def enrichment_worker(state: IncidentState) -> dict:
    """Focused ATT&CK enrichment — no auth logs, no severity."""
    assert (
        "routing" in state
    ), "enrichment_worker requires router_node to have run first"
    prompt = f"""Identify up to 3 MITRE ATT&CK techniques for this alert. Cite each with ID, name, tactics, and a one-sentence why_relevant. 
    If no clear fit, return empty list.

    Alert (class={state['routing'].alert_class.value}): {state['raw']}"""
    # Reuse the run_with_tools_structured path but with a narrower schema
    from .agent_loop import run_with_tools_structured

    try:
        result = run_with_tools_structured(
            prompt,
            output_model=EnrichmentResult,
            max_rounds=8,
            max_tokens=1200,
        )
        if not isinstance(result, EnrichmentResult):
            raise TypeError("structured enrichment result is not EnrichmentResult")
        return {"enrichment": result.techniques, "workers_run": ["enrichment"]}
    except RuntimeError as e:
        if "max_rounds" in str(e):
            # Graceful degradation: return empty enrichment rather than crash chain
            return {"enrichment": [], "workers_run": ["enrichment:degraded"]}
        raise


def identity_worker(state: IncidentState) -> dict:
    """Focused identity analysis via query_auth_logs — no ATT&CK, no severity."""
    assert "routing" in state, "identity_worker requires router_node to have run first"
    prompt = f"""Investigate identity signals for this alert. Use query_auth_logs for
any users mentioned (hours=336). Return an IdentitySignals object with the boolean
flags set based on the auth log patterns you find.

Alert: {state['raw']}
"""
    from .agent_loop import run_with_tools_structured

    try:
        result = run_with_tools_structured(
            prompt,
            output_model=IdentitySignals,
            max_rounds=8,
            max_tokens=1000,
        )
    except RuntimeError as e:
        if "max_rounds" in str(e):
            # If the identity worker fails to converge, return empty signals but still
            # mark it as having run.
            return {"identity": IdentitySignals(), "workers_run": ["identity:degraded"]}
        raise
    return {"identity": result, "workers_run": ["identity"]}


def assessment_worker(state: IncidentState) -> dict:
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


def escalation_router(state: IncidentState) -> str:
    """After evaluator passes, decide whether the incident is high-priority."""
    if state.get("escalated"):
        return "escalated"
    inv = state.get("investigation")
    if inv and inv.severity.value in ("high", "critical"):
        return "escalated"
    return "normal"


def escalation_notification_node(state: IncidentState) -> dict:
    """Log or notify — for now, just marks the state. Week 6 wires HITL here."""
    assert (
        "investigation" in state
    ), "escalation_notification_node requires assessment_worker to have run first"
    print(
        f"[ESCALATION] Incident {state['incident_id']} flagged: "
        f"severity={state['investigation'].severity.value}, "
        f"itdr_escalated={state.get('escalated', False)}"
    )
    return {"workers_run": ["escalation_notification"]}


# --- Orchestrator (conditional edge) ----------------------------------------


def orchestrator(state: IncidentState) -> list[str]:
    """Pick which workers to fan out to, based on alert class.

    Returning a list of node names tells LangGraph to run them in parallel.
    """
    assert "routing" in state, "orchestrator requires router_node to have run first"
    cls = state["routing"].alert_class
    workers = ["enrichment"]  # always enrich
    if cls == "identity_auth":
        workers.append("identity")
    return workers


def build_triage_graph(checkpointer=None):
    """Compose the graph. Pass a checkpointer to enable resumability."""
    builder = StateGraph(IncidentState)

    # Existing nodes (Week 3, renamed/repurposed)
    builder.add_node("router", router_node)
    builder.add_node("enrichment_worker", enrichment_worker)
    builder.add_node("assessment_worker", assessment_worker)
    builder.add_node("evaluator", evaluator_node)
    builder.add_node("increment_refinement", increment_refinement_node)

    # NEW Week 4 nodes
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("itdr_specialist", itdr_specialist_node)  # Section 3
    builder.add_node("soc_analyst_worker", soc_analyst_worker_node)  # below

    # Flow: START → router → supervisor → (worker | assessment | end)
    builder.add_edge(START, "router")
    builder.add_edge("router", "supervisor")

    # Every worker returns to the supervisor for the next decision
    builder.add_edge("enrichment_worker", "supervisor")
    builder.add_edge("itdr_specialist", "supervisor")
    builder.add_edge("soc_analyst_worker", "supervisor")

    # Assessment goes to evaluator; evaluator loops or exits via refinement router
    builder.add_edge("assessment_worker", "evaluator")

    """
    builder.add_conditional_edges(
        "evaluator",
        refinement_router,  # existing from Week 3
        {"refine": "increment_refinement", "end": END},
    )
    """
    builder.add_node("escalation_notification", escalation_notification_node)

    def _pass_through(state):
        return {}

    builder.add_node("post_eval", _pass_through)

    builder.add_conditional_edges(
        "evaluator",
        refinement_router,
        {"refine": "increment_refinement", "end": "post_eval"},
    )
    builder.add_conditional_edges(
        "post_eval",
        escalation_router,
        {"escalated": "escalation_notification", "normal": END},
    )
    builder.add_edge("escalation_notification", END)

    builder.add_edge("increment_refinement", "supervisor")

    # The supervisor's routing decision drives everything
    builder.add_conditional_edges(
        "supervisor",
        supervisor_router,
        {
            "enrichment_worker": "enrichment_worker",
            "itdr_specialist": "itdr_specialist",
            "soc_analyst_worker": "soc_analyst_worker",
            "assessment_worker": "assessment_worker",
            "__end__": END,
        },
    )
    return builder.compile(checkpointer=checkpointer)


# Module-level default with in-memory checkpointer
_checkpointer = MemorySaver()
triage_graph = build_triage_graph(checkpointer=_checkpointer)


def graph_triage(raw_alert: str) -> IncidentState:
    initial = new_incident_state(raw_alert)
    config: RunnableConfig = {"configurable": {"thread_id": initial["incident_id"]}}
    return cast(IncidentState, triage_graph.invoke(initial, config=config))


def graph_triage_streaming(raw_alert: str) -> Iterator[dict]:
    """Yield state updates as each node completes. Consumer decides what to display."""
    initial = new_incident_state(raw_alert)
    config: RunnableConfig = {"configurable": {"thread_id": initial["incident_id"]}}
    for update in triage_graph.stream(initial, config=config, stream_mode="updates"):
        yield update
