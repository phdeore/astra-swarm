"""Astra-Swarm tool registry — Day 3 stub tool for ATT&CK lookup.

Day 4 replaces the stub with a real STIX-backed lookup; the tool contract
(name, schema, return shape) stays the same, so downstream code doesn't move.
"""

from __future__ import annotations

import json
from typing import Any, Callable

# --- Stub ATT&CK catalog — Day 3 only ---------------------------------------
# Three techniques chosen because they map to Astra-Swarm's ITDR focus (Day 21):
# T1078 valid-account abuse, T1110 brute force, T1566 phishing (an initial-access path).
_STUB_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactics": [
            "Defense Evasion",
            "Persistence",
            "Privilege Escalation",
            "Initial Access",
        ],
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as a "
            "means of gaining Initial Access, Persistence, Privilege Escalation, or "
            "Defense Evasion. Compromised credentials may be used to bypass access "
            "controls placed on various resources on systems within the network and may "
            "even be used for persistent access to remote systems and externally "
            "available services."
        ),
        "detection": (
            "Monitor for suspicious account behavior across systems that share accounts. "
            "Correlate logins with physical access, VPN, and MFA events to spot use of "
            "credentials outside expected contexts."
        ),
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["Credential Access"],
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts when "
            "passwords are unknown or when password hashes are obtained. Without knowledge "
            "of the password, an adversary may systematically guess it using a repetitive "
            "or iterative mechanism."
        ),
        "detection": (
            "Monitor authentication logs for high rates of login failures on valid "
            "accounts. Sudden bursts of failures across many accounts from a single "
            "source, or against a single account from many sources, are strong signals."
        ),
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactics": ["Initial Access"],
        "description": (
            "Adversaries may send phishing messages to gain access to victim systems. All "
            "forms of phishing are electronically delivered social engineering. Phishing "
            "can be targeted (spearphishing) or opportunistic."
        ),
        "detection": (
            "Network intrusion detection systems and email gateways can detect phishing "
            "with malicious attachments in transit. Anti-virus can identify malicious "
            "documents that are downloaded and executed on the user's system."
        ),
    },
}


# --- The actual function ----------------------------------------------------
def lookup_attack_technique(technique_id: str) -> dict[str, Any]:
    """Return canned ATT&CK technique detail for a given ID.

    Day 3 stub — hardcoded data. Day 4 swaps this for a real STIX lookup.
    Contract: same input, same return shape.
    """
    tid = technique_id.strip().upper()
    if tid in _STUB_TECHNIQUES:
        return _STUB_TECHNIQUES[tid]
    return {
        "id": tid,
        "error": (
            f"Technique {tid} not in stub catalog. "
            f"Known IDs: {sorted(_STUB_TECHNIQUES)}"
        ),
    }


# --- Tool schema for the Messages API ---------------------------------------
# This is the JSON the model sees; the `description` is the model's only guide
# to when to call the tool, so write it as carefully as a prompt.
LOOKUP_ATTACK_TECHNIQUE_TOOL: dict[str, Any] = {
    "name": "lookup_attack_technique",
    "description": (
        "Look up detailed information about a MITRE ATT&CK technique by its ID "
        "(e.g. 'T1078', 'T1110', 'T1566'). Returns the technique name, associated "
        "tactic(s), description, and detection guidance. Use this whenever you need "
        "authoritative context about what an ATT&CK technique means, how it is used "
        "by adversaries, or how it can be detected."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "technique_id": {
                "type": "string",
                "description": (
                    "MITRE ATT&CK technique ID such as 'T1078' or 'T1566.002'. "
                    "Case-insensitive."
                ),
            },
        },
        "required": ["technique_id"],
    },
}


# --- Registry + dispatch ----------------------------------------------------
# The registry maps tool name → callable. Adding a tool = adding an entry here
# (and appending its schema to whatever list you pass to `tools=` in the API call).
TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "lookup_attack_technique": lookup_attack_technique,
}

ALL_TOOL_SCHEMAS: list[dict[str, Any]] = [
    LOOKUP_ATTACK_TECHNIQUE_TOOL,
]


def dispatch_tool(name: str, tool_input: dict[str, Any]) -> str:
    """Execute a tool by name; return its result as a string.

    tool_result content blocks accept strings; dicts/lists get JSON-encoded.
    Exceptions become JSON error payloads so the model can react rather than crash.
    """
    if name not in TOOL_REGISTRY:
        return json.dumps({"error": f"unknown tool: {name}"})
    try:
        result = TOOL_REGISTRY[name](**tool_input)
    except (
        Exception
    ) as e:  # noqa: BLE001 — we want to surface any tool failure to the model
        return json.dumps({"error": f"tool raised: {type(e).__name__}: {e}"})
    return result if isinstance(result, str) else json.dumps(result)
