"""Local eval runner — no LangSmith dependency. Runs the graph against the golden set,
scores with local evaluators, writes eval_report.json, exits non-zero on regression."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from astra_swarm.evaluators import ALL_EVALUATORS
from astra_swarm.graph import graph_triage
from langsmith.schemas import Example, Run

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
    run_obj = Run(outputs=predicted, inputs={}, id="run-id", run_type="chain")
    example_obj = Example(outputs=expected, inputs={}, id="example-id")

    scores = [ev(run_obj, example_obj) for ev in ALL_EVALUATORS]
    return {"predicted": predicted, "scores": [s.__dict__ for s in scores]}


def main():
    golden_path = Path("evals/week5_golden_set.json")
    labels = json.loads(golden_path.read_text())

    per_example = []
    aggregates: dict[str, list[float]] = defaultdict(list)
    failures_by_alert = []  # NEW

    for i, label in enumerate(labels):
        print(
            f"[{i+1}/{len(labels)}] {label['expected_routing']} ...",
            end=" ",
            flush=True,
        )
        try:
            outcome = run_and_score(label["alert"], label)
            per_example.append(outcome)
            for s in outcome["scores"]:
                aggregates[s["key"]].append(s["score"])
            print("done")
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

    means = {k: sum(v) / len(v) for k, v in aggregates.items()}
    failures = [k for k, v in means.items() if v < THRESHOLDS.get(k, 0)]

    report = {
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
        sys.exit(1)
    print("\n✓ All metrics above threshold")


if __name__ == "__main__":
    main()
