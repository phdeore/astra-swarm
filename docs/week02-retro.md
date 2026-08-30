# Astra-Swarm - Milestone 2 Retrospective
Single-agent pipeline: a cheap router classifies each alert, then a specialist ReAct agent investigates using three tools (ATT&CK by ID, ATT&CK search, auth logs) and commits to a structured verdict.
Attempted prompt caching per the sprint plan.  Astra-Swarm's current cacheable prefix (~1,000 tokens) is below threshold, so caching provides no benefit at Week 2's context size. Re-evaluate in Week 3 once LangGraph state grows the context.

## What was built
src/astra_swarm/router.py
AlertClass - enum: IDENTITY_AUTH, MALWARE, NETWORK, PHISHING, OTHER
RoutingDecision - Pydantic model: alert_class, rationale, confidence
SPECIALIST_SYSTEM_PROMPTS
classify_alert(raw) - one strict-schema call, no tools, returns RoutingDecision

src/astra_swarm/react_agent.py
AgentInvestigation - Pydantic output schema: attack_techniques, identity_signals, key_findings, severity, severity_rationale, confidence, recommended_response, rounds_used
react_triage(raw_alert, routing, max_rounds=10) - runs tool loop with specialist system prompt, returns AgentInvestigation

src/astra_swarm/auth_logs.py — identity-signal data source.
_log_path() — lazy env-var resolution (ASTRA_AUTH_LOG_PATH)
_load() — one-time load of the synthetic auth log fixture into memory
query_auth_logs(user, hours) — returns login counts, unique IPs/geos, MFA challenge count, failures, and recent entries for a user over a lookback window

src/astra_swarm/pipeline.py — the Week 2 entry point.
Week2TriageResult — Pydantic model: raw, routing, investigation
astra_swarm_triage(raw_alert) — orchestrates classify_alert(...) then react_triage(...), returns a fully typed result

Updated files

src/astra_swarm/tools.py
Added query_auth_logs function wrapper
Added QUERY_AUTH_LOGS_TOOL schema with strict: true
Registered in TOOL_REGISTRY and appended to ALL_TOOL_SCHEMAS

src/astra_swarm/agent_loop.py — three foundational fixes.
_M = TypeVar("_M", bound=BaseModel) so run_with_tools_structured returns the concrete Pydantic type the caller passed (no more BaseModel casts)
system parameter broadened to str | list[dict[str, Any]] | None to support cache_control-blocked prompts
Post-injects rounds_used on the returned model when the schema declares that field — the runner is now the source of truth for loop count, not the model

src/astra_swarm/alerts.py — same _M TypeVar fix on _ask_structured.

## What worked
Verified the caching path works with a >4,096-token block (Haiku 4.5's minimum).

## What broke
Astra-Swarm's current cacheable prefix (~1,000 tokens) is below threshold, so caching provides no benefit at Week 2's context size.