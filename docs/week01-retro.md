# Astra-Swarm - Milestone 1 Retrospective

A single-pass, tool-augmented alert triage pipeline.

## What was built

A chain of four Pydantic-typed stages, wired end-to-end and validated against 10 synthetic alerts.
Each stage is grammar-constrained with JSON output. The summary is free-form text.

- `parse_alert` — raw alert → `ParsedAlert` (entities, indicators, description)
- `enrich_with_attack` — parsed alert → `AttackEnrichment` (via MITRE ATT&CK STIX lookup tools)
- `summarize` — parsed alert → analyst-voice prose
- `assess_severity` — parsed alert + summary → `SeverityVerdict` (severity, rationale, confidence)

Supporting infrastructure:
`attack_kb.py` (Enterprise ATT&CK STIX index),
`agent_loop.py::run_with_tools[_structured]` (round-trip runner with cap),
`cassette.py` (record/replay for cheap iteration).

## What worked

- Strict structured outputs killed the JSON-parsing fragility.
- Replacing the ATT&CK stub with real STIX data required zero changes to the tool loop.
- Per-step error wrapping in `triage_chain` turned opaque failures into legible ones — the failing step name is in every traceback.
- **Cassette-based replay** made post-hoc iteration free, which changes the day-to-day economics.

## What broke

- **`_parse_json` on preamble/postamble in enrichment output** — the tool loop encourages the model to narrate, and narration leaks into "final" answers. The structured outputs killed the problem class entirely.
- **`max_rounds` too tight for some alerts** — one converged at round 7; my cap was 6. Chose graceful degradation (return empty enrichment + honest summary) over raising the cap.
- **`SeverityVerdict.confidence`'s Pydantic bounds shipped to Anthropic's grammar** and 400'd the request. Fix: `to_strict_schema` now strips unsupported JSON Schema keywords; `field_validator` enforces the bound client-side only.
- **Stale module cache in Colab after push** was easily half of my "why does it still fail" moments. Fix: `%autoreload 2` at the top of every notebook.

## Metrics on the alerts

- Severity distribution: <fill in from Cell 4>
- ATT&CK techniques cited: <total>, <unique>. Top: <list>
- Graceful degradation rate: <n>/10
- Honest "no ATT&CK fit": <n>/10
- Confidence: mean <x.xx>, range <x.xx> to <x.xx>

## Cost baseline

- Week 1 total API spend (Anthropic Console): $1.83
- Cassette replay used for rerunning saved costs. Will store the cassette directory on Google Drive so that the files can be used across runtime restarts.
