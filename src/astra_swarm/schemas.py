# src/astra_swarm/schemas.py
"""Astra-Swarm incident schema — v0.1 (Day 1 draft)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


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
