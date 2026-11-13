"""Local eval runner — no LangSmith dependency. Runs the graph against the golden set,
scores with local evaluators, writes eval_report.json, exits non-zero on regression.

Modes (--mode):
  replay  (default) Replay recorded Claude responses from evals/cassettes/. No API
          key, no network calls to Anthropic, no cost. Used on every pull request.
  record  Call the real API and (re)write evals/cassettes/. Needs credentials.
  live    Call the real API without touching cassettes.

Exit codes: 0 ok, 1 metric regression, 2 replay miss (code or prompts changed since
the cassettes were recorded — re-record them).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Must be set before astra_swarm.cassette is imported anywhere.
CASSETTE_DIR = Path(os.environ.setdefault("ASTRA_CASSETTE_DIR", "evals/cassettes"))

from astra_swarm.cassette import CassetteMiss, cassette  # noqa: E402
from astra_swarm.evaluators import ALL_EVALUATORS  # noqa: E402
from astra_swarm.graph import graph_triage  # noqa: E402
from langsmith.schemas import Example, Run  # noqa: E402

EXIT_REGRESSION = 1
EXIT_REPLAY_MISS = 2

THRESHOLDS = {
    "routing_correctness": 0.70,  # baseline 0.80
    "severity_correctness": 0.70,  # baseline 0.80
    "trajectory_correctness": 0.75,  # baseline 0.84
    "escalation_correctness": 0.65,  # baseline 0.75
}


def run_and_score(alert: str, expected: dict) -> dict:
    result = graph_triage(alert)
    assert "investigation" in result, "result requires investigation."
    inv = result.get("investigation")  # may be None if guardrail quarantine path
    routing = result.get("routing")  # may be None if guardrail flagged before routing
    predicted = {
        "routing": routing.model_dump() if routing else None,
        "investigation": inv.model_dump() if inv else None,
        "workers_run": result.get("workers_run", []),
        "escalated": result.get("escalated", False),
        "guardrail_flagged": result.get("guardrail_flagged", False),  # for debugging
    }
    # Local stand-ins for LangSmith objects; only .outputs is read by the evaluators.
    # Newer langsmith validates ids as UUIDs and requires name/start_time.
    run_id = uuid.uuid4()
    run_obj = Run(
        id=run_id,
        trace_id=run_id,
        name="graph_triage",
        start_time=datetime.now(timezone.utc),
        run_type="chain",
        inputs={},
        outputs=predicted,
    )
    example_obj = Example(id=uuid.uuid4(), inputs={}, outputs=expected)

    scores = [ev(run_obj, example_obj) for ev in ALL_EVALUATORS]
    return {"predicted": predicted, "scores": [s.__dict__ for s in scores]}


def cassette_name(alert: str) -> str:
    """Key cassettes by alert content so reordering the golden set doesn't break replay."""
    return "eval-" + hashlib.sha256(alert.encode()).hexdigest()[:12]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--mode", choices=("replay", "record", "live"), default="replay")
    args = parser.parse_args()

    golden_path = Path("evals/week5_golden_set.json")
    labels = json.loads(golden_path.read_text())

    if args.mode == "replay" and not any(CASSETTE_DIR.glob("eval-*.json")):
        print(
            f"::warning::No recorded cassettes in {CASSETTE_DIR}/ yet — skipping the eval. "
            "Run the 'Record eval cassettes' workflow to create them."
        )
        return

    per_example = []
    aggregates: dict[str, list[float]] = defaultdict(list)
    failures_by_alert = []  # NEW
    replay_misses = []

    for i, label in enumerate(labels):
        print(
            f"[{i+1}/{len(labels)}] {label['expected_routing']} ...",
            end=" ",
            flush=True,
        )
        if args.mode == "live":
            recorder = contextlib.nullcontext()
        else:
            recorder = cassette(cassette_name(label["alert"]), mode=args.mode)
        try:
            with recorder:
                outcome = run_and_score(label["alert"], label)
            per_example.append(outcome)
            for s in outcome["scores"]:
                aggregates[s["key"]].append(s["score"])
            print("done")
        except CassetteMiss as e:
            print(f"REPLAY MISS: {e}")
            replay_misses.append({"index": i, "alert_preview": label["alert"][:120]})
            continue
        except Exception as e:
            print(f"CRASHED: {type(e).__name__}: {e}")
            failures_by_alert.append(
                {
                    "index": i,
                    "expected_routing": label["expected_routing"],
                    "alert_preview": label["alert"][:120],
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
            )
            # Add zeros for every metric so aggregates aren't misleading
            for key in (
                "routing_correctness",
                "severity_correctness",
                "trajectory_correctness",
                "escalation_correctness",
            ):
                aggregates[key].append(0.0)

    if replay_misses:
        print(
            f"\n::error::{len(replay_misses)} of {len(labels)} alert(s) made requests that "
            "are not in the recorded cassettes, so prompts, tool output or graph logic "
            "changed since recording. Re-record with the 'Record eval cassettes' workflow "
            "and commit the result."
        )
        for m in replay_misses:
            print(f"  [{m['index']+1}] {m['alert_preview'][:80]}")
        sys.exit(EXIT_REPLAY_MISS)

    means = {k: sum(v) / len(v) for k, v in aggregates.items()}
    failures = [k for k, v in means.items() if v < THRESHOLDS.get(k, 0)]

    report = {
        "mode": args.mode,
        "aggregates": means,
        "thresholds": THRESHOLDS,
        "threshold_failures": failures,
        "per_example": per_example,
        "crashed_examples": failures_by_alert,  # NEW
        "total_examples": len(labels),
        "successful_examples": len(labels) - len(failures_by_alert),
    }
    Path("eval_report.json").write_text(json.dumps(report, indent=2, default=str))

    print("\n=== Scorecard ===")
    for k, v in means.items():
        status = "✓" if v >= THRESHOLDS.get(k, 0) else "✗"
        print(f"  {status} {k}: {v:.2%}  (threshold: {THRESHOLDS.get(k, 0):.0%})")
    if failures_by_alert:
        print(
            f"\n⚠ {len(failures_by_alert)} alert(s) crashed — see eval_report.json 'crashed_examples'"
        )
        for f in failures_by_alert:
            print(f"  [{f['index']+1}] {f['error_type']}: {f['error_message'][:80]}")
    if failures:
        print(f"\n❌ REGRESSION on: {failures}")
        sys.exit(EXIT_REGRESSION)
    print("\n✓ All metrics above threshold")


if __name__ == "__main__":
    main()
