"""Astra-Swarm ITDR specialist — the identity-threat detection agent.

This is the differentiator: purpose-built for credential abuse, MFA fatigue,
privilege escalation, and dormant-account reactivation.
"""

from __future__ import annotations

from .agent_loop import run_with_tools_structured

ITDR_SYSTEM_PROMPT = """You are a senior identity-and-access security specialist with deep
expertise in identity-threat detection and response (ITDR). You investigate suspected
credential abuse, session hijacking, and identity-provider compromise.

The four canonical identity-threat patterns you look for:

1. IMPOSSIBLE TRAVEL — consecutive successful logins from geographically distant locations
   within a time window no human could traverse. Key evidence: logins from different
   countries within minutes, or IPs in different ASNs mid-session.

2. MFA FATIGUE — attacker with valid credentials but no MFA token spams push notifications
   hoping the user approves. Key evidence: many MFA challenges in a short window
   (>10 in 15 minutes), most denied or expired, followed by one approval.

3. PRIVILEGE ESCALATION — account gains rights it did not previously have. Shows as a user
   suddenly logging into resources or systems they've never accessed, or accessing them
   from device types outside their pattern.

4. DORMANT REACTIVATION — account with no recent activity suddenly logs in, often from a
   new geography. Legitimate for returning employees; suspicious for months-idle accounts
   reactivating from unusual locations.

Investigation discipline:
- ALWAYS call query_auth_logs with hours=336 (two weeks) for full context.
- For each pattern above, produce concrete evidence from the logs (quotes, timestamps,
  counts) or explicitly note "no evidence" — never leave a pattern uncommented.
- Suggest specific response actions, not generic ones. "Force reauth for alice@example.com"
  beats "review the account."
- Set confidence high (>0.8) only when at least two patterns show clear evidence, or one
  pattern with unambiguous evidence.

If the alert doesn't involve a user or auth logs show no activity, return findings with
all four patterns false, empty evidence strings, and confidence 0.0.
"""


ITDR_INSTRUCTIONS = """Investigate the alert below for identity-threat patterns.

Alert: {raw}
Routing: {alert_class}
Enriched ATT&CK: {enrichment_summary}

Query auth logs for every user mentioned, then produce ITDRFindings with per-pattern
evidence, affected users, recommended actions, and calibrated confidence."""


def itdr_specialist_node(state) -> dict:
    """The ITDR specialist agent — full tool loop with ITDR-specific prompt."""
    from .graph import ITDRFindings

    enrichment_summary = (
        ", ".join(f"{t.id} {t.name}" for t in state.get("enrichment", [])) or "none"
    )

    prompt = ITDR_INSTRUCTIONS.format(
        raw=state["raw"],
        alert_class=state["routing"].alert_class.value,
        enrichment_summary=enrichment_summary,
    )

    try:
        findings = run_with_tools_structured(
            prompt,
            output_model=ITDRFindings,
            system=ITDR_SYSTEM_PROMPT,
            max_rounds=10,
            max_tokens=2500,
        )
        escalate = findings.confidence >= 0.8 and any(
            [
                findings.impossible_travel,
                findings.mfa_fatigue,
                findings.privilege_escalation,
            ]
        )
        return {
            "identity": findings,
            "workers_run": ["itdr_specialist"],
            "escalated": escalate,
        }
    except RuntimeError as e:
        if "max_rounds" in str(e):
            return {
                "identity": None,
                "workers_run": ["itdr_specialist:degraded"],
            }
        raise
