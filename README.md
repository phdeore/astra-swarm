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
| `anthropic-wif-test` (`anthropic-wif-test.yml`) | manual, approval-gated | No: token exchange only | Same federation setup; optional diagnostic |

PR runs replay recorded Claude responses, so they cost nothing and are safe for PRs
from forks. When a change alters prompts, tool output or graph flow, replay misses and
the job fails with exit code 2. Re-record, review and commit the cassettes:

    gh workflow run record-eval.yml --ref <your-branch>   # then approve it in the Actions tab
    gh run download <run-id> -n eval-cassettes-golden       # puts evals/cassettes/ in place
    git add evals/cassettes && git commit -m "Re-record eval cassettes"

Locally: `python scripts/run_eval.py` (replay, default), `--mode record`, or `--mode live`.

**Datasets.** `--dataset golden` (default) is the 20-alert hand-written set and the only
one that gates PRs. `--dataset real_world` (`evals/real_world_set.json`, built from public
detection data) has its own cassettes (`evals/cassettes/real_world/`), auth-log fixture
and report (`evals/real_world_report.json`). It reports without thresholds, and the PR job
never fails on it. Every report includes 95% bootstrap intervals, a per-class breakdown
and a routing confusion matrix. How that set is built from OTRF lab data with Hayabusa and
Suricata, its licences and the label review are in
[evals/real_world_SOURCES.md](evals/real_world_SOURCES.md).

A recording can be split across jobs with `--shard N/M`, which runs every M-th alert. Each
alert has its own cassette, so the shards combine. A sharded run never gates; replay the
whole set afterwards for the real scorecard:

    gh workflow run record-eval.yml -f dataset=real_world -f shard=1/2   # and shard=2/2
    gh run download <run-id> -n eval-cassettes-real_world-shard-1of2

### One-time setup for recording

No GitHub organization is needed: environments with required reviewers are free for
public repos on a personal account. (On a private repo they need GitHub Pro/Team.)

1. **GitHub environment (do this first):** Settings → Environments → `ci-eval` (create it
   if missing). If the workflow runs before this exists, GitHub creates the environment
   automatically *without* the approval gate.
   - **Required reviewers:** add yourself. Leave *Prevent self-review* unticked, or a
     sole maintainer can never approve a run.
   - **Deployment branches:** *No restriction*, because recordings run from feature
     branches. The approval is the gate.
   - No wait timer and no environment secrets.
   - Verify: `gh api repos/phdeore/astra-swarm/environments/ci-eval --jq '.protection_rules'`
     shows a `required_reviewers` entry.
2. **Claude Console workspace:** Settings → Workspaces → create a dedicated workspace
   (e.g. `astra-ci`) with a low monthly **spend limit** (e.g. $5–10). CI usage is then
   capped and billed separately. **Do not create an API key for it**: CI authenticates
   with federation only.
3. **Claude Console workload** (needs admin/owner): Settings → Workload identity →
   **Connect workload** → **GitHub Actions**:
   - issuer `https://token.actions.githubusercontent.com` (discovery)
   - rule subject, exact (no `*`):
     `repo:phdeore@9942420/astra-swarm@1331674356:environment:ci-eval`
     (audience `https://api.anthropic.com`).
     This repo uses GitHub's *immutable* subject format, which embeds the owner and
     repo numeric IDs. These keep the rule working after a rename and stop a new repo
     with the same name from matching it. Check the prefix with
     `gh api repos/<owner>/<repo>/actions/oidc/customization/sub` (`sub_claim_prefix`).
     If it shows `use_immutable_subject: false`, the subject is
     `repo:<owner>/<repo>:environment:ci-eval` instead. A subject that doesn't match
     shows as `match_subject_prefix` in the Console's authentication events.
   - claims: `repository_owner: phdeore` (optional with the immutable subject, which
     already pins the owner and repo IDs). Don't add `ref`/`job_workflow_ref`: they
     contain the branch name and would block feature-branch recordings.
   - *Where can workloads authenticate?* Only the workspace from step 2.
   - scope `workspace:developer` (inference only, not admin); token lifetime 600 s.
   - Make sure the new service account is a member of that workspace.
4. **GitHub variables:** copy the rule, organization and service account IDs shown
   after saving into `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID` and
   `ANTHROPIC_SERVICE_ACCOUNT_ID`. Store them as *Variables*, not secrets; the IDs
   aren't sensitive. Set them either under the `ci-eval` environment (preferred: only
   the approved job sees them) or repo-wide under Settings → Secrets and variables →
   Actions. `ANTHROPIC_WORKSPACE_ID` is only needed if the rule allows more than one
   workspace.
5. Delete any `ANTHROPIC_API_KEY` repository secret. CI no longer reads one, and the
   record job fails if a key is present, because a key would override federation.

### How a recording run authenticates

Nothing is stored or carried over between runs; every run mints its own token:

1. `permissions: id-token: write` lets the job request a GitHub OIDC token for that run.
2. A background loop fetches one (audience `https://api.anthropic.com`) into
   `$RUNNER_TEMP` and refreshes it every 2 minutes. GitHub tokens live about 5 minutes.
3. The Anthropic SDK exchanges the token for a short-lived Anthropic access token
   (about 10 minutes) and re-reads the file whenever that access token expires.

The rule matches on `sub`, which depends only on the repo and the `ci-eval`
environment, so it is the same for every workflow and branch. `anthropic-wif-test` does
the exchange without calling Claude. It's useful when setting up the rule, but
`record-eval.yml` never depends on it.

**Troubleshooting** (`status.reason` in the error or the Console's authentication events):

- `match_subject_prefix` / `match_claim_value_mismatch`: a rule condition doesn't match
  the token. `anthropic-wif-test` prints the token's claims; compare them with the rule
  field by field.
- `jti_reused`: Anthropic accepts each GitHub token only once. Keep a single
  `Anthropic()` client (`src/astra_swarm/client.py`). Each client exchanges the token on
  its own.

**Local recording (optional):** `--mode record`/`--mode live` on your machine needs an
API key. Create it in the same capped workspace and export it only in your shell
session; never commit it or add it to GitHub. Delete it afterwards. Replay needs no
credentials.

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