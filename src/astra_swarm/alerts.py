"""Rewrite: strict structured outputs end to end."""

from __future__ import annotations

import json
import re
from typing import Any

from anthropic import Anthropic
from pydantic import BaseModel, ValidationError

from .schemas import (
    AttackEnrichment,
    ParsedAlert,
    SeverityVerdict,
    to_strict_schema,
)

_client = Anthropic()
_MODEL = "claude-haiku-4-5-20251001"


# --- Helpers ----------------------------------------------------------------
def _parse_json(text: str) -> Any:
    """Kept from Day 4 — still useful for the free-form paths."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    stripped = re.sub(r"^\s*```(?:json)?\s*", "", text)
    stripped = re.sub(r"\s*```\s*$", "", stripped)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    candidates = [i for i in (text.find("{"), text.find("[")) if i != -1]
    if not candidates:
        raise ValueError(f"no JSON found; raw: {text[:300]!r}")
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
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError as e:
                    raise ValueError(f"malformed JSON: {e}") from e
    raise ValueError("unbalanced brackets")


def _ask_structured(
    prompt: str,
    model_cls: type[BaseModel],
    *,
    system: str | None = None,
    max_tokens: int = 1024,
    max_repairs: int = 1,
) -> BaseModel:
    """Call Claude with an output_config schema; validate with Pydantic; repair on failure.

    The grammar guarantees valid JSON of the right shape. Pydantic catches semantic
    violations the grammar can't express (numeric ranges, cross-field invariants).
    On Pydantic failure we do one repair pass with the validation error in the prompt.
    """
    schema = to_strict_schema(model_cls)
    current_prompt = prompt

    for attempt in range(max_repairs + 1):
        kwargs: dict[str, Any] = {
            "model": _MODEL,
            "max_tokens": max_tokens,
            "output_config": {"format": {"type": "json_schema", "schema": schema}},
            "messages": [{"role": "user", "content": current_prompt}],
        }
        if system:
            kwargs["system"] = system

        response = _client.messages.create(**kwargs)
        raw = "".join(b.text for b in response.content if b.type == "text")

        try:
            data = json.loads(raw)
            return model_cls.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as e:
            if attempt >= max_repairs:
                raise ValueError(
                    f"{model_cls.__name__} validation failed after {attempt + 1} attempt(s): "
                    f"{e}. Raw: {raw[:300]!r}"
                ) from e
            current_prompt = (
                f"{prompt}\n\nYour previous response failed validation:\n{e}\n"
                f"Return corrected JSON that satisfies all constraints."
            )


# --- Step 1: parse (strict) --------------------------------------------------
def parse_alert(raw: str) -> ParsedAlert:
    prompt = f"""Extract structured fields from this raw security alert. If a field is
not present, use an empty string or empty list — do not invent values.

Raw alert:
{raw}
"""
    return _ask_structured(prompt, ParsedAlert, max_tokens=800)  # type: ignore[return-value]


# --- Step 2: enrich (strict + tools) -----------------------------------------
def enrich_with_attack(parsed: ParsedAlert) -> AttackEnrichment:
    from .agent_loop import run_with_tools_structured

    prompt = f"""You are a SOC analyst. Identify up to 3 MITRE ATT&CK techniques that best
describe the adversary behavior in this parsed alert. You MUST call a lookup tool for
every technique you cite — do not include any technique you have not looked up.

Constraints on your search:
- Look up at most 4 candidate techniques total, across both tools.
- If your first two searches don't surface a strongly-relevant technique, stop and
  return an empty techniques list — an honest "no clear fit" beats speculation.
- Once you have your 3 techniques (or have decided none fit), commit to the final
  answer. Do not keep searching for confirmation.

Parsed alert:
{parsed.model_dump_json(indent=2)}
"""
    try:
        return run_with_tools_structured(
            prompt,
            output_model=AttackEnrichment,
            max_rounds=6,
            max_tokens=1500,
        )
    except RuntimeError as e:
        if "max_rounds" in str(e):
            # Graceful degradation: return empty enrichment rather than crash chain
            return AttackEnrichment(
                techniques=[],
                summary=f"Enrichment inconclusive within {6}-round budget.",
            )
        raise


# --- Step 3: summarize (stays free-form) -------------------------------------
def summarize(parsed: ParsedAlert) -> str:
    """Analyst-voice prose; no schema. Not every step wants JSON."""
    prompt = f"""You are a Tier 1 SOC analyst. Given this parsed alert, write a 2-3 sentence
summary in analyst voice — what happened, who is affected, what is notable. Plain prose.

Parsed alert:
{parsed.model_dump_json(indent=2)}
"""
    resp = _client.messages.create(
        model=_MODEL,
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in resp.content if b.type == "text").strip()


# --- Step 4: severity (strict) -----------------------------------------------
def assess_severity(parsed: ParsedAlert, summary: str) -> SeverityVerdict:
    prompt = f"""Assign a preliminary severity to this alert. Use the NIST 800-61 style
factors — functional impact, information impact, recoverability, scope, asset criticality —
implicitly in your rationale.

Parsed alert:
{parsed.model_dump_json(indent=2)}

Summary:
{summary}
"""
    return _ask_structured(prompt, SeverityVerdict, max_tokens=400)  # type: ignore[return-value]


# --- The chain ---------------------------------------------------------------
class TriageResult(BaseModel):
    """The full end-to-end typed contract for a triaged alert."""

    raw: str
    parsed: ParsedAlert
    attack: AttackEnrichment
    summary: str
    verdict: SeverityVerdict


def triage_chain(raw_alert: str) -> TriageResult:
    def _step(name: str, fn):
        try:
            return fn()
        except Exception as e:
            raise RuntimeError(
                f"chain step {name!r} failed: {type(e).__name__}: {e}"
            ) from e

    parsed = _step("parse_alert", lambda: parse_alert(raw_alert))
    if not parsed.description:
        raise ValueError("parse step returned no description; aborting chain")
    attack = _step("enrich_with_attack", lambda: enrich_with_attack(parsed))
    summary = _step("summarize", lambda: summarize(parsed))
    verdict = _step("assess_severity", lambda: assess_severity(parsed, summary))
    return TriageResult(
        raw=raw_alert, parsed=parsed, attack=attack, summary=summary, verdict=verdict
    )


# --- Unchanged --------------------------------------------------
def generate_synthetic_alerts(n: int = 5) -> list[str]:
    prompt = f"""Generate {n} realistic raw security alert strings, separated by a line
containing only '---'. Vary source (firewall, EDR, SIEM, WAF, DLP, IAM), format
(syslog, JSON, CEF, key=value), and severity mix. Include realistic entities.
Return only the alerts and separators. No numbering or commentary.
"""
    resp = _client.messages.create(
        model=_MODEL,
        max_tokens=2500,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    return [a.strip() for a in text.split("---") if a.strip()][:n]
