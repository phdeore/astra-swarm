# src/astra_swarm/schemas.py
"""Astra-Swarm incident schema — v0.1 (Day 1 draft)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any

from pydantic import BaseModel, Field, field_validator

_UNSUPPORTED_KEYWORDS = {
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
    "format",
    "multipleOf",
}


def to_strict_schema(model_cls: type[BaseModel]) -> dict[str, Any]:
    """Produce an Anthropic-strict-mode-compatible JSON Schema from a Pydantic model.

    Adjustments:
      1. Every object gets `additionalProperties: false`.
      2. Every property is added to `required`.
      3. Keywords the strict grammar does not support are stripped
         (enforcement stays client-side via Pydantic validators).
    """
    schema = model_cls.model_json_schema()

    def _tighten(node: Any) -> None:
        if not isinstance(node, dict):
            return
        for kw in _UNSUPPORTED_KEYWORDS & node.keys():
            del node[kw]
        if node.get("type") == "object" and "properties" in node:
            node["required"] = list(node["properties"].keys())
            node["additionalProperties"] = False
            for prop in node["properties"].values():
                _tighten(prop)
        for key in ("anyOf", "allOf", "oneOf"):
            if key in node:
                for s in node[key]:
                    _tighten(s)
        if "items" in node:
            _tighten(node["items"])
        for defs_key in ("$defs", "definitions"):
            if defs_key in node:
                for s in node[defs_key].values():
                    _tighten(s)

    _tighten(schema)
    return schema


class AlertClass(str, Enum):
    MALWARE = "malware"
    IDENTITY_AUTH = "identity_auth"
    NETWORK = "network"
    PHISHING = "phishing"
    OTHER = "other"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IdentitySignals(BaseModel):
    """Populated by the ITDR specialist agent (built Day 21)."""

    impossible_travel: bool = False
    mfa_fatigue: bool = False
    privilege_escalation: bool = False
    dormant_account_reactivation: bool = False
    notes: str = ""


class ProposedAction(BaseModel):
    """A response step Astra-Swarm recommends. Simulated only — never executed."""

    action: str  # e.g. "disable_user", "isolate_host"
    target: str  # e.g. "alice@example.com", "web-03"
    rationale: str
    requires_approval: bool = True  # default: always ask a human


class Incident(BaseModel):
    """The unit that flows through Astra-Swarm from ingest to human review."""

    # --- identity ---
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # --- provenance ---
    source_alert_ids: list[str] = Field(default_factory=list)

    # --- classification ---
    alert_class: AlertClass
    entities_users: list[str] = Field(default_factory=list)
    entities_hosts: list[str] = Field(default_factory=list)
    entities_ips: list[str] = Field(default_factory=list)

    # --- enrichment ---
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs, e.g. T1078, T1110.",
    )
    enrichment_notes: str = ""
    correlation_notes: str = ""
    identity_signals: Optional[IdentitySignals] = None

    # --- assessment ---
    severity: Severity
    severity_rationale: str
    confidence: float = Field(ge=0.0, le=1.0)

    # --- response ---
    recommended_response: str
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    requires_human_approval: bool = True


class ParsedAlert(BaseModel):
    """Output shape of parse_alert — the raw-alert-to-structured-fields step."""

    source_system: str = Field(description="Tool/system that emitted the alert")
    timestamp: str = Field(description="When the event occurred, verbatim from alert")
    entities_users: list[str] = Field(description="Users, usernames, emails")
    entities_hosts: list[str] = Field(description="Hostnames")
    entities_ips: list[str] = Field(description="IP addresses")
    indicators: list[str] = Field(
        description="Suspicious values — hashes, domains, ports, techniques"
    )
    description: str = Field(description="One-sentence factual summary")


class AttackTechniqueCitation(BaseModel):
    """One MITRE ATT&CK technique cited by the enrichment step."""

    id: str = Field(description="Technique ID like T1078 or T1078.001")
    name: str = Field(description="Technique name")
    tactics: list[str] = Field(description="Associated MITRE ATT&CK tactic names")
    why_relevant: str = Field(
        description="One sentence connecting technique to the alert"
    )


class AttackEnrichment(BaseModel):
    """Output shape of enrich_with_attack."""

    techniques: list[AttackTechniqueCitation] = Field(
        description="Up to 3 cited techniques; may be empty if none clearly fit"
    )
    summary: str = Field(description="One sentence tying techniques to the alert")


class SeverityVerdict(BaseModel):
    severity: Severity
    rationale: str = Field(description="One sentence explaining the severity choice")
    confidence: float = Field(description="0.0 to 1.0")

    @field_validator("confidence")
    @classmethod
    def _confidence_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {v}")
        return v
