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

## Evaluation and CI

| Workflow | Trigger | Calls Claude? | Credentials |
|---|---|---|---|
| `Astra-Swarm Eval` (`eval.yml`) | every PR | No: replays `evals/cassettes/` | None |
| `Record eval cassettes` (`record-eval.yml`) | manual, approval-gated | Yes (one eval run) | Workload Identity Federation, no API key |

PR runs replay recorded Claude responses, so they cost nothing and are safe for PRs
from forks. When a change alters prompts, tool output or graph flow, replay misses and
the job fails with exit code 2. Re-record, review and commit the cassettes:

    gh workflow run record-eval.yml --ref <your-branch>   # then approve it in the Actions tab
    gh run download <run-id> -n eval-cassettes              # puts evals/cassettes/ in place
    git add evals/cassettes && git commit -m "Re-record eval cassettes"

Locally: `python scripts/run_eval.py` (replay, default), `--mode record`, or `--mode live`.

### One-time setup for recording

1. **GitHub environment (do this first):** Settings → Environments → New environment
   `ci-eval` → enable **Required reviewers** (add yourself). If the workflow runs before
   this exists, GitHub creates the environment automatically *without* the approval gate.
2. **Claude Console** (needs admin/owner): Settings → Workload identity → **Connect
   workload** → **GitHub Actions**, with:
   - issuer `https://token.actions.githubusercontent.com` (discovery)
   - rule subject `repo:phdeore/astra-swarm:environment:ci-eval` (exact, no `*`),
     audience `https://api.anthropic.com`, claims `repository_owner: phdeore`
   - scope `workspace:developer`, token lifetime 600 s; add the new service account to
     the workspace that should be billed
3. **GitHub variables** (Settings → Secrets and variables → Actions → *Variables*, not
   secrets; these IDs are not sensitive): `ANTHROPIC_FEDERATION_RULE_ID`,
   `ANTHROPIC_ORGANIZATION_ID`, `ANTHROPIC_SERVICE_ACCOUNT_ID`, and
   `ANTHROPIC_WORKSPACE_ID` if the rule spans more than one workspace.
4. Delete any `ANTHROPIC_API_KEY` repository secret: CI no longer reads one.

Reproducibility inputs: the ATT&CK bundle is pinned to a tagged release and
SHA-256-verified (`attack_kb.py`), and auth-log lookback windows are measured from the
newest log entry rather than the wall clock (override with
`ASTRA_AUTH_LOG_REFERENCE_TIME`). Changing either requires re-recording.

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