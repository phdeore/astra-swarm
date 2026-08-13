from __future__ import annotations

import json
import re
from typing import Any

from anthropic import Anthropic

_client = Anthropic()
MODEL = "claude-haiku-4-5-20251001"


def _ask(prompt: str, system: str | None = None, max_tokens: int = 800) -> str:
    """Single-shot Claude call; returns concatenated text."""
    kwargs: dict[str, Any] = {
        "model": MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system
    resp = _client.messages.create(**kwargs)

    return "".join(b.text for b in resp.content if b.type == "text")


def _parse_json(text: str) -> dict:
    """Best-effort JSON extraction; strips ``` fences if the model adds them."""
    text = re.sub(r"^\s*```(?:json)?\s*", "", text.strip())
    text = re.sub(r"\s*```\s*$", "", text)
    return json.loads(text)


# --- Step 1: parse a raw alert into structured fields ------------------------
def parse_alert(raw: str) -> dict:
    prompt = f"""You are a SOC alert parser. Extract these fields from the raw alert.
Return ONLY valid JSON. If a field is not present, use an empty string or empty list.

Fields:
- source_system: the tool/system that emitted it (firewall, EDR, SIEM, WAF, DLP, IAM, etc.)
- timestamp: when the event occurred (verbatim from the alert)
- entities_users: list of user IDs, usernames, or email addresses
- entities_hosts: list of hostnames
- entities_ips: list of IP addresses
- indicators: list of suspicious values (hashes, domains, unusual ports, technique IDs, etc.)
- description: one-sentence factual summary of what the alert says happened

Raw alert:
{raw}
"""
    return _parse_json(_ask(prompt, max_tokens=800))


# --- Step 2: summarize in analyst voice --------------------------------------
def summarize(parsed: dict) -> str:
    prompt = f"""You are a Tier 1 SOC analyst. Given this parsed alert, write a 2-3 sentence
summary in analyst voice — what happened, who is affected, what is notable. Plain prose.
No headers, no bullets, no lead-in like "Summary:".

Parsed alert:
{json.dumps(parsed, indent=2)}
"""
    return _ask(prompt, max_tokens=300).strip()


# --- Step 3: assess preliminary severity -------------------------------------
def assess_severity(parsed: dict, summary: str) -> dict:
    prompt = f"""You are a SOC analyst assigning preliminary severity. Return ONLY JSON with:
- severity: one of "low", "medium", "high", "critical"
- rationale: one sentence explaining the choice
- confidence: float from 0.0 to 1.0

Parsed alert:
{json.dumps(parsed, indent=2)}

Summary:
{summary}
"""
    return _parse_json(_ask(prompt, max_tokens=200))


# --- The chain ---------------------------------------------------------------
def triage_chain(raw_alert: str) -> dict:
    """Run parse → summarize → assess_severity in sequence."""
    parsed = parse_alert(raw_alert)
    # A light gate — catch a totally-empty parse before wasting more tokens.
    if not parsed.get("description"):
        raise ValueError("parse_alert step returned no description; aborting chain")
    summary = summarize(parsed)
    verdict = assess_severity(parsed, summary)
    return {"raw": raw_alert, "parsed": parsed, "summary": summary, "verdict": verdict}


# --- Synthetic alert generator (for Day 2 fixtures) --------------------------
def generate_synthetic_alerts(n: int = 5) -> list[str]:
    prompt = f"""Generate {n} realistic raw security alert strings, separated by a line
containing only '---'. Vary these axes:
- source (firewall, EDR, SIEM, WAF, DLP, IAM/identity provider)
- format (syslog, JSON, CEF, key=value)
- severity mix (some benign or medium; one or two that clearly warrant investigation)
- realistic entities: users (email or samAccountName), hostnames, IPs, hashes,
  MITRE ATT&CK technique IDs where relevant

Return only the alert strings and the '---' separators. No numbering, no commentary.
"""
    text = _ask(prompt, max_tokens=2500)
    parts = [a.strip() for a in text.split("---") if a.strip()]
    return parts[:n]
