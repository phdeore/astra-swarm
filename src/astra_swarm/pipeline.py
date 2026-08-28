"""Astra-Swarm Week 2 pipeline entry point — router + ReAct agent."""

from __future__ import annotations

from pydantic import BaseModel

from .react_agent import AgentInvestigation, react_triage
from .router import RoutingDecision, classify_alert


class Week2TriageResult(BaseModel):
    raw: str
    routing: RoutingDecision
    investigation: AgentInvestigation


def astra_swarm_triage(raw_alert: str) -> Week2TriageResult:
    """One entry point: router → specialist ReAct agent → verdict."""
    routing = classify_alert(raw_alert)
    investigation = react_triage(raw_alert, routing)
    return Week2TriageResult(
        raw=raw_alert,
        routing=routing,
        investigation=investigation,
    )
