"""Astra-Swarm input guardrails — defense-in-depth for untrusted alert text."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Prompt-injection patterns known from public red-team datasets.
# Not exhaustive — this is a tripwire, not a cure. False positives will happen;
# they should be reviewed rather than silently accepted.
_INJECTION_PATTERNS = [
    r"ignore\s+(?:previous|prior|above|all)\s+(?:instructions?|prompts?|rules?)",
    r"you\s+are\s+now\s+(?:a|an)\s+",
    r"forget\s+(?:everything|all)\s+(?:above|before|previous)",
    r"new\s+(?:instructions?|rules?|role)\s*:",
    r"system\s*prompt\s*:",
    r"</?(?:system|assistant|user)>",  # role-injection tags
    r"###\s*(?:instruction|end|new)",  # separator-injection
]

_MAX_ALERT_LENGTH = 8000  # generous but bounded — real alerts don't exceed this


@dataclass
class GuardrailVerdict:
    """Structured verdict for guardrail decisions. Callers decide whether to raise or log."""

    passed: bool
    reason: str = ""
    matched_patterns: list[str] = None  # type: ignore

    def __post_init__(self):
        if self.matched_patterns is None:
            self.matched_patterns = []


def validate_alert_input(raw: str) -> GuardrailVerdict:
    """Layered validation on incoming alert text.

    Returns a GuardrailVerdict — caller decides how to handle a failure.
    Prefer logging the verdict and continuing with the alert (marking it
    quarantined) over hard-refusing, so an operator can review what tripped.
    """
    if not isinstance(raw, str):
        return GuardrailVerdict(passed=False, reason="alert is not a string")

    if not raw.strip():
        return GuardrailVerdict(passed=False, reason="alert is empty")

    if len(raw) > _MAX_ALERT_LENGTH:
        return GuardrailVerdict(
            passed=False,
            reason=f"alert exceeds max length ({len(raw)} > {_MAX_ALERT_LENGTH})",
        )

    # Prompt-injection tripwire
    matched = [p for p in _INJECTION_PATTERNS if re.search(p, raw, re.IGNORECASE)]
    if matched:
        return GuardrailVerdict(
            passed=False,
            reason="prompt injection pattern detected",
            matched_patterns=matched,
        )

    return GuardrailVerdict(passed=True)


# Tool allow-lists per specialist agent — each worker sees only its own tools
TOOL_ALLOWLIST: dict[str, set[str]] = {
    "enrichment_worker": {"lookup_attack_technique_by_id", "search_attack_techniques"},
    "itdr_specialist": {"query_auth_logs"},
    "soc_analyst_worker": {"lookup_attack_technique_by_id", "search_attack_techniques"},
    # assessment_worker and evaluator use no tools
}


def filtered_tool_schemas(agent_name: str, all_schemas: list[dict]) -> list[dict]:
    """Return only the tools this agent is allowed to call."""
    allowed = TOOL_ALLOWLIST.get(agent_name, set())
    if not allowed:
        return []
    return [s for s in all_schemas if s["name"] in allowed]
