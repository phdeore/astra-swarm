"""Astra-Swarm ReAct triage agent — replaces the fixed chain with a single agent
that decides what to investigate at each step."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .agent_loop import run_with_tools_structured
from .router import RoutingDecision, specialist_prompt_for
from .schemas import AttackTechniqueCitation, IdentitySignals, Severity


class AgentInvestigation(BaseModel):
    """What the ReAct agent produces after investigating an alert."""

    attack_techniques: list[AttackTechniqueCitation] = Field(
        description="ATT&CK techniques cited (empty list if no clear fit)"
    )
    identity_signals: Optional[IdentitySignals] = Field(
        description="Only populated if the agent queried auth logs and found signals"
    )
    key_findings: str = Field(description="2-3 sentence summary")
    severity: Severity
    severity_rationale: str
    confidence: float = Field(description="0.0 to 1.0")
    recommended_response: str
    # Filled in by run_with_tools_structured after the loop completes;
    # the model doesn't need to know about this field.
    rounds_used: int = Field(
        default=0, description="How many tool-loop rounds were used"
    )


AGENT_INSTRUCTIONS = """You are investigating a security alert. You have tools available:
- lookup_attack_technique_by_id: if you know an ATT&CK ID
- search_attack_techniques: to search ATT&CK by keyword
- query_auth_logs: to investigate a user's recent authentication behavior

Reason step by step. Investigate what matters for THIS alert. When you have enough
evidence to commit to a severity and response, produce the final structured output.

Constraints:
- Do not cite ATT&CK techniques you have not looked up.
- If the alert involves a specific user, query their auth logs at least once
  (use hours=336 to cover the full fixture window).
- Aim for 3-6 tool calls total. If you're past 6 and still uncertain, commit anyway
  with lower confidence — an honest medium-confidence verdict beats an infinite loop.
- If no clear ATT&CK fits, empty list is acceptable.
- If no user is involved, identity_signals stays null."""


def react_triage(
    raw_alert: str,
    routing: RoutingDecision,
    max_rounds: int = 10,
) -> AgentInvestigation:
    """Run the ReAct agent on one alert with a specialist system prompt."""
    system = specialist_prompt_for(routing.alert_class) + "\n\n" + AGENT_INSTRUCTIONS

    prompt = f"""Alert (class={routing.alert_class.value}):
{raw_alert}

Routing rationale: {routing.rationale}

Investigate and produce your final assessment as structured output."""

    return run_with_tools_structured(
        prompt,
        output_model=AgentInvestigation,
        system=system,
        max_rounds=max_rounds,
        max_tokens=2000,
    )
