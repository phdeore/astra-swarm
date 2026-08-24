"""Astra-Swarm router — classify raw alerts into specialist categories."""

from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field, field_validator

from .schemas import to_strict_schema
from .alerts import _ask_structured  # your Day 5 strict-schema helper


class AlertClass(str, Enum):
    IDENTITY_AUTH = "identity_auth"
    MALWARE = "malware"
    NETWORK = "network"
    PHISHING = "phishing"
    OTHER = "other"


class RoutingDecision(BaseModel):
    alert_class: AlertClass
    rationale: str = Field(description="One sentence explaining the classification")
    confidence: float = Field(description="0.0 to 1.0")

    @field_validator("confidence")
    @classmethod
    def _bounded(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"confidence out of range: {v}")
        return v


# Specialist system prompts — the "personality" each downstream agent adopts.
# These are deliberately different from a generic SOC prompt. Sharpen them
# during Day B prompt engineering; today just get them serviceable.
SPECIALIST_SYSTEM_PROMPTS: dict[AlertClass, str] = {
    AlertClass.IDENTITY_AUTH: (
        "You are a senior identity-and-access security analyst specializing in "
        "authentication anomalies, credential & token abuse, SSO/MFA anomalies, "
        "impossible-travel, brute force, IAM/directory service modifications, "
        "and privilege escalation. Reason about *who* was involved and *whether* "
        "the account behavior is consistent with the legitimate user's pattern."
    ),
    AlertClass.MALWARE: (
        "You are a senior malware analyst. Reason about the file/process signals, "
        "Endpoint/host-level process execution, suspicious binary behavior, "
        "EDR alerts, memory injections, or host quarantine actions, "
        "known IoCs, and the ATT&CK techniques the behavior evidences."
    ),
    AlertClass.NETWORK: (
        "You are a senior network security analyst. Reason about traffic patterns, "
        "Network perimeter and transit events including Firewall/WAF detections, "
        "IDS/IPS alerts, DNS tunneling, unusual port/protocol activity, "
        "volumetric spikes, egress destinations, lateral-movement signals, or "
        "unexpected outbound egress."
    ),
    AlertClass.PHISHING: (
        "You are a senior email/phishing analyst. Reason about sender reputation, "
        "Inbound/outbound email telemetry, suspicious attachments, "
        "credential harvesting links, BEC attempts, or user-reported suspicious mail, "
        "link and attachment indicators, and downstream user actions."
    ),
    AlertClass.OTHER: (
        "You are a senior SOC generalist. Reason carefully about what the alert "
        "actually evidences and whether it warrants deeper investigation. Reason about "
        "Physical security, operational/availability issues, infrastructure misconfigurations, "
        "or events not mapping directly to the classes above."
    ),
}


def classify_alert(raw: str) -> RoutingDecision:
    """Cheap Haiku classifier — one strict-schema call, no tools."""
    prompt = f"""Classify this raw security alert into one of these classes:
- identity_auth: login anomalies, MFA issues, credential events, IAM changes
- malware: process/file signals, EDR detections, known-bad hashes
- network: firewall, IDS/IPS, unusual protocols, egress alerts
- phishing: email, malicious links or attachments, user-reported suspicious mail
- other: doesn't clearly fit above

Return your classification with a one-sentence rationale and a confidence score.

Raw alert:
{raw}
"""
    return _ask_structured(prompt, RoutingDecision, max_tokens=300)


def specialist_prompt_for(cls: AlertClass) -> str:
    return SPECIALIST_SYSTEM_PROMPTS.get(
        cls, SPECIALIST_SYSTEM_PROMPTS[AlertClass.OTHER]
    )
