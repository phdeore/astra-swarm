"""Astra-Swarm tool registry — Day 4 update: real ATT&CK KB backing."""

from __future__ import annotations

import json
from typing import Any, Callable

from . import attack_kb


def lookup_attack_technique(
    technique_id: str | None = None,
    keyword: str | None = None,
) -> dict[str, Any]:
    """Look up ATT&CK techniques by exact ID OR by keyword.

    Provide exactly one input. If both are given, technique_id wins.
    Contract for the ID path is unchanged from Day 3.
    """
    if technique_id:
        return attack_kb.lookup_by_id(technique_id)
    if keyword:
        matches = attack_kb.search_by_keyword(keyword, limit=5)
        if not matches:
            return {
                "keyword": keyword,
                "matches": [],
                "note": f"No ATT&CK techniques matched '{keyword}'.",
            }
        return {"keyword": keyword, "matches": matches}
    return {"error": "provide either 'technique_id' or 'keyword'"}


LOOKUP_ATTACK_TECHNIQUE_TOOL: dict[str, Any] = {
    "name": "lookup_attack_technique",
    "description": (
        "Look up MITRE ATT&CK Enterprise techniques. Provide EITHER an exact "
        "technique_id (like 'T1078' or 'T1566.002') OR a keyword to search by "
        "name and description (like 'brute force', 'phishing', 'valid accounts'). "
        "Returns technique name, tactic(s), platforms, data sources, and description. "
        "Use this whenever you need authoritative ATT&CK context for a technique, or "
        "when a raw alert describes activity without naming a specific ID."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "technique_id": {
                "type": "string",
                "description": "Exact ID (case-insensitive). Use when you know it.",
            },
            "keyword": {
                "type": "string",
                "description": "Freeform search string. Use when you don't have an ID.",
            },
        },
        # No 'required' — the function accepts either. The description above tells
        # the model to pick one.
    },
}


TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "lookup_attack_technique": lookup_attack_technique,
}

ALL_TOOL_SCHEMAS: list[dict[str, Any]] = [LOOKUP_ATTACK_TECHNIQUE_TOOL]


def dispatch_tool(name: str, tool_input: dict[str, Any]) -> str:
    """Unchanged from Day 3."""
    if name not in TOOL_REGISTRY:
        return json.dumps({"error": f"unknown tool: {name}"})
    try:
        result = TOOL_REGISTRY[name](**tool_input)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"tool raised: {type(e).__name__}: {e}"})
    return result if isinstance(result, str) else json.dumps(result)
