# Astra-Swarm — Project Charter

## What it is

A multi-agent SOC and Identity-Threat-Detection-and-Response (ITDR) triage system built on
Anthropic Claude, orchestrated with LangGraph, traced and evaluated in LangSmith. It ingests raw
security alerts and authentication logs, enriches them with MITRE ATT&CK and threat-intel context,
correlates related alerts into incidents, runs a dedicated identity-threat analysis, drafts a
response, and pauses for human approval before any consequential action.

## Why it exists

A learning capstone that also serves as a portfolio artifact for cybersecurity-firm interviews.
It targets the product areas of CrowdStrike / SentinelOne (agentic SOC), Palo Alto Networks
(correlation and playbook automation), Okta / SailPoint (ITDR), and Google Mandiant
(threat-intel enrichment).

## Non-goals

- No real remediation. All response actions are simulated and logged, never wired to a live system.
- No real production telemetry. All data is public (MITRE ATT&CK, Sigma, NVD) or synthetic.
- No local model hosting. All inference goes through the Anthropic API.

## Success criteria (by Day 36)

- A deployed multi-agent graph reachable over an endpoint.
- Full run-tree tracing in LangSmith.
- An eval harness reporting precision/recall against a labeled golden set of 30–50 incidents,
  wired as a regression gate in GitHub Actions.
- A human-in-the-loop approval interrupt before every state-changing action.
- A recorded demo and a written architecture / threat-model / ATT&CK-coverage document.

## Constraints

- Single developer, ~2 hrs/day for 6 weeks.
- Cost target: single-digit dollars of API spend over the full 6 weeks
  (Haiku default + prompt caching + Batch API on evals).
- All secrets in Colab Secrets, never in code.
