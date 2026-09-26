"""Astra-Swarm evaluators for LangSmith eval runs."""

from __future__ import annotations

from typing import Any
from langsmith.evaluation import EvaluationResult
from langsmith.schemas import Run, Example


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
    """Did the supervisor call the workers we expected?"""
    if run.outputs is None or example.outputs is None:
        return EvaluationResult(
            key="trajectory_correctness", score=0.0, comment="missing outputs"
        )

    workers_run = set(run.outputs.get("workers_run", []))
    expected = set(example.outputs.get("expected_workers_contains", []))

    if not expected:
        return EvaluationResult(
            key="trajectory_correctness", score=1.0, comment="no requirements"
        )

    matched = expected & {
        w.split(":")[0] for w in workers_run
    }  # strip :degraded suffix
    score = len(matched) / len(expected)

    return EvaluationResult(
        key="trajectory_correctness",
        score=score,
        comment=f"matched={sorted(matched)} required={sorted(expected)}",
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
