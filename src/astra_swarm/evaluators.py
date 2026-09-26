"""Astra-Swarm evaluators for LangSmith eval runs."""

from __future__ import annotations

from typing import Any
from langsmith.evaluation import EvaluationResult
from langsmith.schemas import Run, Example

# Structural workers that don't reflect supervisor decisions
_STRUCTURAL_WORKERS = {"assessment", "escalation_notification", "guardrail_quarantine"}


def routing_correctness(run: Run, example: Example) -> EvaluationResult:
    if run.outputs is None or example.outputs is None:
        return EvaluationResult(
            key="routing_correctness", score=0.0, comment="missing outputs"
        )
    routing = run.outputs.get("routing") or {}  # ← handles None
    predicted = routing.get("alert_class", "")
    expected = example.outputs.get("expected_routing", "")
    return EvaluationResult(
        key="routing_correctness",
        score=1.0 if predicted == expected else 0.0,
        comment=f"predicted={predicted or 'null'} expected={expected}",
    )


def severity_correctness(run: Run, example: Example) -> EvaluationResult:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if run.outputs is None or example.outputs is None:
        return EvaluationResult(
            key="severity_correctness", score=0.0, comment="missing outputs"
        )
    inv = run.outputs.get("investigation") or {}  # ← handles None
    predicted = inv.get("severity")
    expected = example.outputs.get("expected_severity", "")
    if predicted is None:
        return EvaluationResult(
            key="severity_correctness", score=0.0, comment="no severity produced"
        )
    p, e = order.get(predicted, -1), order.get(expected, -1)
    if p == -1 or e == -1:
        return EvaluationResult(
            key="severity_correctness", score=0.0, comment=f"unknown levels"
        )
    diff = abs(p - e)
    score = {0: 1.0, 1: 0.5, 2: 0.0}.get(min(diff, 2), 0.0)
    return EvaluationResult(
        key="severity_correctness",
        score=score,
        comment=f"predicted={predicted} expected={expected} diff={diff}",
    )


def trajectory_correctness(run: Run, example: Example) -> EvaluationResult:
    if run.outputs is None or example.outputs is None:
        return EvaluationResult(
            key="trajectory_correctness", score=0.0, comment="missing outputs"
        )

    # Only compare specialist workers — structural ones always run
    workers = {
        w.split(":")[0] for w in run.outputs.get("workers_run", [])
    } - _STRUCTURAL_WORKERS
    required = (
        set(example.outputs.get("expected_workers_contains", [])) - _STRUCTURAL_WORKERS
    )

    if not required:
        return EvaluationResult(
            key="trajectory_correctness", score=1.0, comment="no requirement"
        )

    # Jaccard: penalizes both misses and unnecessary extras
    intersection = required & workers
    union = required | workers
    score = len(intersection) / len(union) if union else 0.0

    return EvaluationResult(
        key="trajectory_correctness",
        score=score,
        comment=(
            f"matched={sorted(intersection)} "
            f"extra={sorted(workers - required)} "
            f"missing={sorted(required - workers)}"
        ),
    )


def escalation_correctness(run: Run, example: Example) -> EvaluationResult:
    """Did we escalate when we should have?"""
    if run.outputs is None or example.outputs is None:
        return EvaluationResult(
            key="escalation_correctness", score=0.0, comment="missing outputs"
        )

    predicted = run.outputs.get("escalated", False)
    expected = example.outputs.get("expected_escalation", False)

    return EvaluationResult(
        key="escalation_correctness",
        score=1.0 if predicted == expected else 0.0,
        comment=f"predicted={predicted} expected={expected}",
    )
