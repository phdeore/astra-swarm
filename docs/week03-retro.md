# Astra-Swarm - Milestone 2 Retrospective
Moved from hand written Python orchestration (i.e. calling functions in sequence) to a LangGraph state machine with explicit nodes, edges and typed shared state. Three patterns: evaluator-optimizer self correction loop, orchestrator-workers parallel fan-out to specialist workers and entity based correlation grouping related triaged alerts into incidents.

## What was built
src/astra_swarm/graph.py — the LangGraph state machine
src/astra_swarm/correlation.py — post-processing to group related triaged alerts into incidents.

Updated files:
src/astra_swarm/alerts.py — no signature changes; _ask_structured continues as the helper the evaluator node uses.

src/astra_swarm/react_agent.py — no changes to signatures; react_triage still exists but is no longer called by the graph (the workers replaced it). Kept for backwards compatibility with Week 2 notebooks.

src/astra_swarm/pipeline.py — no changes required; the Week 2 pipeline still works, but the Week 3 flow uses graph.graph_triage instead. Both entry points coexist for A/B comparison.

New data & docs:
data/synthetic/week03_triage_results.json — 10 alerts run through the full LangGraph pipeline including evaluator scores, worker fan-out traces, and any refinements.
data/synthetic/week03_incidents.json — output of correlate() on the above, showing which alerts grouped into incidents by shared entities.
docs/week03-retro.md — this document.

New notebook:
notebooks/week3_milestone.ipynb — full 10-alert graph run, Mermaid rendering of the compiled graph at each build stage, metrics on refinement rate, worker fan-out distribution, evaluator score averages, and correlation collapse ratio.

## What worked
The porting was smooth & clean (wrapping classify_alert and react_triage as LangGraph nodes). The graph compiled and executed without any errors.
Evaluator-optimizer: Roughly a fifth of alerts triggered refinement passes and the refined assessments scored higher on the second run than the first. Capped at one refinement to keep the cost controlled. The 3 criterion evaluation (completeness, citation quality, severity defensibility) proved more useful than a single overall score.

## What broke
Worker max_rounds=4 was too tight. Workers doing multi-step ATT&CK searches or auth-log queries hit that cap on harder alerts and raised RuntimeError: hit max_rounds. Fix was two-part: bump caps to 8, and wrap workers in graceful-degradation try/except so a cap hit becomes a :degraded trace tag instead of a chain-crashing exception.
Prompt caching remained ineffective with week 3 context sizes. With, the specialist prompts, tool schemas and system context, the threshold didn't reach. 