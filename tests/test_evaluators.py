"""Scoring rules the golden and real-world reports depend on."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from langsmith.schemas import Example, Run

from astra_swarm.evaluators import (
    escalation_correctness,
    routing_correctness,
    severity_correctness,
    trajectory_correctness,
)


def _run(**outputs) -> Run:
    rid = uuid.uuid4()
    return Run(
        id=rid,
        trace_id=rid,
        name="t",
        start_time=datetime.now(UTC),
        run_type="chain",
        inputs={},
        outputs=outputs,
    )


def _example(**outputs) -> Example:
    return Example(id=uuid.uuid4(), inputs={}, outputs=outputs)


def test_routing_exact_match_and_quarantined_alert():
    ex = _example(expected_routing="malware")
    assert routing_correctness(_run(routing={"alert_class": "malware"}), ex).score == 1.0
    assert routing_correctness(_run(routing={"alert_class": "network"}), ex).score == 0.0
    assert routing_correctness(_run(routing=None), ex).score == 0.0  # guardrail path


@pytest.mark.parametrize(
    "predicted,expected,score",
    [
        ("high", "high", 1.0),
        ("high", "critical", 0.5),
        ("medium", "low", 0.5),
        ("low", "high", 0.0),
        ("low", "critical", 0.0),
    ],
)
def test_severity_partial_credit(predicted, expected, score):
    run = _run(investigation={"severity": predicted})
    assert severity_correctness(run, _example(expected_severity=expected)).score == score


def test_severity_missing_investigation():
    assert severity_correctness(_run(investigation=None), _example(expected_severity="low")).score == 0.0


def test_trajectory_ignores_structural_workers_and_degraded_suffix():
    ex = _example(expected_workers_contains=["enrichment", "itdr_specialist"])
    run = _run(workers_run=["enrichment:degraded", "itdr_specialist", "assessment"])
    assert trajectory_correctness(run, ex).score == 1.0


def test_trajectory_jaccard_penalizes_extras_and_misses():
    ex = _example(expected_workers_contains=["enrichment"])
    run = _run(workers_run=["enrichment", "soc_analyst"])
    assert trajectory_correctness(run, ex).score == 0.5
    run = _run(workers_run=["soc_analyst"])
    assert trajectory_correctness(run, ex).score == 0.0


@pytest.mark.parametrize("predicted,expected,score", [(True, True, 1.0), (False, True, 0.0), (False, False, 1.0)])
def test_escalation(predicted, expected, score):
    assert escalation_correctness(_run(escalated=predicted), _example(expected_escalation=expected)).score == score
