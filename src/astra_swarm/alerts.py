from __future__ import annotations

import json
import re
from typing import Any

from anthropic import Anthropic
from matplotlib import text
from .agent_loop import run_with_tools

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


def _parse_json(text: str):
    """Extract a JSON object or array from Claude's output, tolerating prose and code fences."""
    text = text.strip()

    # Fast path
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strip ''' fences
    stripped = re.sub(r"^\s*```(?:json)?\s*", "", text)
    stripped = re.sub(r"\s*```\s*$", "", stripped)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Anchor on whichever of { or [ appears first]}
    candidates = [i for i in (text.find("{"), text.find("[")) if i != -1]
    if not candidates:
        raise ValueError(f"no JSON object or array found; raw: {text[:300]!r}")
    start = min(candidates)

    depth, in_string, escape = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"extracted JSON is malformed: {e}. "
                        f"candidate: {candidate[:300]!r}"
                    ) from e
        raise ValueError(f"unbalanced brackets; raw: {text[:300]!r}")

    return json.loads(text)


# --- Step 1: parse a raw alert into structured fields ------------------------
def parse_alert(raw: str) -> dict:
    prompt = f"""You are a SOC alert parser. Extract these fields from the raw alert. 
    Return ONLY JSON. No preamble, no code fences, no commentary. If a field is not present, 
    use an empty string or empty list.

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


def enrich_with_attack(parsed: dict) -> dict:
    """Ask Claude to identify up to 3 relevant ATT&CK techniques for a parsed alert,
    letting it call the lookup_attack_technique tool as needed."""
    prompt = f"""Return ONLY a single JSON object. No preamble. No explanation. No markdown
code fences. No text before or after the JSON. If you have nothing to say, still return
a valid JSON object with an empty techniques list.

Exact schema:
{{
  "techniques": [
    {{"id": "T####", "name": "...", "tactics": ["..."], "why_relevant": "one sentence"}},
  ],
  "summary": "one sentence tying the techniques to the alert"
}}

Task: identify up to 3 MITRE ATT&CK techniques that best describe the adversary behavior
in the parsed alert below. You MUST call lookup_attack_technique for every technique you
cite — either by ID if you're confident, or by keyword to search. Do not cite any technique
you have not looked up. If no technique clearly fits, return an empty techniques list and
say so in the summary.

Parsed alert:
{json.dumps(parsed, indent=2)}
"""
    result = run_with_tools(prompt, max_rounds=6, max_tokens=1500)
    return _parse_json(result["final_text"])


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
    def _step(name, fn):
        try:
            return fn()
        except Exception as e:
            raise RuntimeError(f"step {name} failed: {type(e).__name__}: {e}") from e

    """Run parse → attack enrichment → summarize → assess_severity in sequence."""
    parsed = _step("parse_alert", lambda: parse_alert(raw_alert))
    # A light gate — catch a totally-empty parse before wasting more tokens.
    if not parsed.get("description"):
        raise ValueError("parse_alert step returned no description; aborting chain")
    attack = _step("enrich_with_attack", lambda: enrich_with_attack(parsed))
    summary = _step("summarize", lambda: summarize(parsed))
    verdict = _step("assess_severity", lambda: assess_severity(parsed, summary))
    return {
        "raw": raw_alert,
        "parsed": parsed,
        "attack": attack,
        "summary": summary,
        "verdict": verdict,
    }


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
