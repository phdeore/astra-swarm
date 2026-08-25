"""Split the tool into two (by technique_id & keyword)"""

from __future__ import annotations

import json
from typing import Any, Callable

from . import attack_kb
from .auth_logs import query_auth_logs as _query_auth_logs_fn


def lookup_attack_technique_by_id(technique_id: str) -> dict[str, Any]:
    return attack_kb.lookup_by_id(technique_id)


def search_attack_techniques(keyword: str, limit: int = 5) -> dict[str, Any]:
    matches = attack_kb.search_by_keyword(keyword, limit=limit)
    if not matches:
        return {
            "keyword": keyword,
            "matches": [],
            "note": f"No ATT&CK techniques matched '{keyword}'.",
        }
    return {"keyword": keyword, "matches": matches}


LOOKUP_BY_ID_TOOL: dict[str, Any] = {
    "name": "lookup_attack_technique_by_id",
    "description": (
        "Look up a MITRE ATT&CK technique by exact ID (case-insensitive), like "
        "'T1078' or 'T1566.002'. Returns technique name, tactic(s), platforms, "
        "data sources, and description. Use when you know the ID."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "technique_id": {"type": "string", "description": "Exact technique ID"},
        },
        "required": ["technique_id"],
        "additionalProperties": False,
    },
    "strict": True,
}

SEARCH_TOOL: dict[str, Any] = {
    "name": "search_attack_techniques",
    "description": (
        "Search MITRE ATT&CK Enterprise techniques by keyword against name and "
        "description (e.g. 'brute force', 'phishing'). Returns up to `limit` matches. "
        "Use when you don't have an exact ID."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "keyword": {"type": "string", "description": "Freeform search string"},
            "limit": {"type": "integer", "description": "Max matches to return (1-10)"},
        },
        "required": ["keyword", "limit"],
        "additionalProperties": False,
    },
    "strict": True,
}


TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "lookup_attack_technique_by_id": lookup_attack_technique_by_id,
    "search_attack_techniques": search_attack_techniques,
}

ALL_TOOL_SCHEMAS: list[dict[str, Any]] = [LOOKUP_BY_ID_TOOL, SEARCH_TOOL]


def dispatch_tool(name: str, tool_input: dict[str, Any]) -> str:
    """Unchanged from Day 3."""
    if name not in TOOL_REGISTRY:
        return json.dumps({"error": f"unknown tool: {name}"})
    try:
        result = TOOL_REGISTRY[name](**tool_input)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"tool raised: {type(e).__name__}: {e}"})
    return result if isinstance(result, str) else json.dumps(result)


def query_auth_logs(user: str, hours: int) -> dict[str, Any]:
    return _query_auth_logs_fn(user, hours)


QUERY_AUTH_LOGS_TOOL: dict[str, Any] = {
    "name": "query_auth_logs",
    "description": (
        "Query recent authentication activity for a specific user over the last N hours. "
        "Returns login counts, unique source IPs, geographic locations, MFA challenge "
        "count, and recent log entries. Use this to investigate credential abuse, "
        "impossible-travel, MFA fatigue, or any alert where identity behavior matters."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "user": {"type": "string", "description": "User email or samAccountName"},
            "hours": {"type": "integer", "description": "Lookback window (1-336)"},
        },
        "required": ["user", "hours"],
        "additionalProperties": False,
    },
    "strict": True,
}

TOOL_REGISTRY["query_auth_logs"] = query_auth_logs
ALL_TOOL_SCHEMAS.append(QUERY_AUTH_LOGS_TOOL)
