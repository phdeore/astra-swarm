"""Astra-Swarm correlation — group triaged alerts into incidents by shared entities."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pydantic import BaseModel

from .graph import TriageState


class Incident(BaseModel):
    """A group of related triage results correlated by shared entities."""

    incident_id: str
    triage_results: list[TriageState]
    shared_entities: dict[str, list[str]]
    highest_severity: str
    alert_count: int

    model_config = {"arbitrary_types_allowed": True}


def _extract_entities(triage: TriageState) -> dict[str, set[str]]:
    """Pull user/host/IP entities from a triage result."""
    inv = triage.get("investigation")
    entities: dict[str, set[str]] = {"users": set(), "hosts": set(), "ips": set()}
    if inv and inv.identity_signals:
        # Best-effort: extract users from identity_signals.notes
        # (Real implementation would have entities as first-class fields — Day 22 refactor.)
        pass
    # Extract from raw alert text using simple patterns
    import re

    raw = triage.get("raw", "")
    entities["users"].update(re.findall(r"\b[\w.-]+@[\w.-]+\b", raw))
    entities["hosts"].update(re.findall(r"\bhost=(\S+)", raw))
    entities["ips"].update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw))
    return entities


def correlate(triage_results: list[TriageState]) -> list[Incident]:
    """Union-find style clustering: two alerts are in the same incident if they
    share any entity (user, host, or IP)."""
    # Extract entities per alert
    per_alert_entities = [_extract_entities(t) for t in triage_results]

    # Build entity → set of alert indices
    entity_to_alerts: dict[tuple[str, str], set[int]] = defaultdict(set)
    for i, ents in enumerate(per_alert_entities):
        for kind, values in ents.items():
            for v in values:
                entity_to_alerts[(kind, v)].add(i)

    # Union-find: merge alerts that share any entity
    parent = list(range(len(triage_results)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for alerts_sharing_entity in entity_to_alerts.values():
        alerts_list = list(alerts_sharing_entity)
        for j in range(1, len(alerts_list)):
            union(alerts_list[0], alerts_list[j])

    # Group by root
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(triage_results)):
        groups[find(i)].append(i)

    # Build Incident objects
    _severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    incidents = []
    for group_id, indices in groups.items():
        group_entities = {"users": set(), "hosts": set(), "ips": set()}
        for i in indices:
            for k, v in per_alert_entities[i].items():
                group_entities[k] |= v

        severities = [
            inv.severity.value
            for i in indices
            if (inv := triage_results[i].get("investigation")) is not None
        ]
        highest = (
            max(severities, key=lambda s: _severity_order.get(s, 0))
            if severities
            else "low"
        )

        incidents.append(
            Incident(
                incident_id=f"INC-{group_id:04d}",
                triage_results=[triage_results[i] for i in indices],
                shared_entities={k: sorted(v) for k, v in group_entities.items() if v},
                highest_severity=highest,
                alert_count=len(indices),
            )
        )
    return sorted(incidents, key=lambda i: -i.alert_count)
