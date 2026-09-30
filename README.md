# Astra-Swarm

A multi-agent Security Operations Center (SOC) + Identity Threat Detection & Response
(ITDR) alert triage system built as a six-week capstone. Runs on LangGraph + Anthropic
Claude Haiku 4.5, deployable via Docker.

**Status:** v1.0-capstone (complete).

## What it does

Takes raw security alerts (CEF, JSON, plain-text) and produces a structured incident
record: ATT&CK-cited enrichment, identity anomaly detection, threat-intel context,
severity assessment, and a human-approval-gated escalation decision.

## Architecture

[embed the Week 2 architecture diagram or a fresher one]

## Try it

    docker run -d -p 8000:8000 \
        -e ANTHROPIC_API_KEY=your_key \
        ghcr.io/phdeore/astra-swarm:v1.0-capstone   # if pushed

    curl -X POST http://localhost:8000/triage \
        -H "Content-Type: application/json" \
        -d '{"alert": "your alert here"}'

Or run locally:

    git clone https://github.com/phdeore/astra-swarm.git
    cd astra-swarm && pip install -e .
    uvicorn astra_swarm.api:app --port 8000

## Measured baseline

Eval scorecard on 20-alert human-reviewed golden set:

| Metric | Score |
|---|---|
| Routing correctness | 0.80 |
| Severity correctness | 0.80 |
| Trajectory correctness | 0.84 |
| Escalation correctness | 0.75 |

CI regression gate runs on every PR; thresholds set 10pp below baseline.

## Design highlights

- **Dynamic supervisor** — LangGraph state machine with a dynamic supervisor node deciding
  which specialist workers to invoke per alert (not static fan-out)
- **ITDR specialist** — dedicated worker for four identity-attack patterns (impossible
  travel, MFA fatigue, privilege escalation, dormant reactivation)
- **Evaluator-optimizer refinement** — post-assessment evaluator triggers one refinement
  loop on weak investigations
- **Guardrails** — input validation, prompt-injection tripwire, tool allow-list per worker
- **Human-in-the-loop** — escalations pause via `interrupt()` for operator approval;
  checkpoint state persists across processes
- **Measured** — 4-evaluator eval harness with CI regression gate

## Tech stack

Python 3.12 · LangGraph · Anthropic Claude Haiku 4.5 · Pydantic v2 · FastAPI · Docker ·
GitHub Actions

## Repo layout

[keep your existing layout section]

## Six-week roadmap

- Week 1 (v0.1) — Single-pass tool-augmented triage
- Week 2 (v0.2) — Router + ReAct specialist agent
- Week 3 (v0.3) — LangGraph state machine + evaluator-optimizer
- Week 4 (v0.4) — Dynamic supervisor + ITDR specialist + checkpointing
- Week 5 (v0.5) — Guardrails + eval harness + CI regression gate
- Week 6 (v1.0) — HITL approval gate + FastAPI/Docker deployment