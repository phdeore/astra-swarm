"""Local eval runner — no LangSmith dependency. Runs the graph against a labelled dataset,
scores with local evaluators, writes a JSON report, exits non-zero on regression.

Datasets (--dataset):
  golden      (default) evals/week5_golden_set.json — 20 hand-written alerts. Gated by
              THRESHOLDS on every pull request.
  real_world  evals/real_world_set.json — alerts derived from public detection data.
              Report only (no thresholds) until a baseline exists.

Modes (--mode):
  replay  (default) Replay recorded Claude responses from the dataset's cassette
          directory. No API key, no network calls to Anthropic, no cost.
  record  Call the real API and (re)write the cassettes. Needs credentials.
  live    Call the real API without touching cassettes.

--shard N/M runs every M-th alert starting at N (1-based), so a long recording can be
split over several jobs. Cassettes are one file per alert, so shards combine cleanly.
A sharded run never gates: replay the whole set afterwards for the real scorecard.

Exit codes: 0 ok, 1 metric regression, 2 replay miss (code or prompts changed since
the cassettes were recorded — re-record them), 3 configuration error.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import random
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from langsmith.schemas import Example, Run

from astra_swarm import auth_logs
from astra_swarm.cassette import CassetteMiss, cassette
from astra_swarm.evaluators import ALL_EVALUATORS
from astra_swarm.graph import graph_triage

EXIT_REGRESSION = 1
EXIT_REPLAY_MISS = 2
EXIT_CONFIG = 3

METRICS = (
    "routing_correctness",
    "severity_correctness",
    "trajectory_correctness",
    "escalation_correctness",
)

THRESHOLDS = {
    "routing_correctness": 0.70,  # baseline 0.80
    "severity_correctness": 0.70,  # baseline 0.80
    "trajectory_correctness": 0.75,  # baseline 0.84
    "escalation_correctness": 0.65,  # baseline 0.75
}


@dataclass(frozen=True)
class DatasetConfig:
    labels: Path
    cassette_dir: Path
    report: Path
    thresholds: dict[str, float] = field(default_factory=dict)
    # None keeps the bundled synthetic fixture. A dataset with its own users must use its
    # own file: auth-log windows are measured from the newest entry, so adding entries to
    # the shared fixture would change tool output for every other dataset's recordings.
    auth_log_path: Path | None = None


DATASETS: dict[str, DatasetConfig] = {
    "golden": DatasetConfig(
        labels=Path("evals/week5_golden_set.json"),
        cassette_dir=Path("evals/cassettes"),
        report=Path("eval_report.json"),
        thresholds=THRESHOLDS,
    ),
    "real_world": DatasetConfig(
        labels=Path("evals/real_world_set.json"),
        cassette_dir=Path("evals/cassettes/real_world"),
        report=Path("evals/real_world_report.json"),
        auth_log_path=Path("evals/real_world_auth_logs.json"),
    ),
}


def parse_shard(value: str) -> tuple[int, int]:
    """'2/3' -> (2, 3). Used as an argparse type."""
    m = re.fullmatch(r"(\d+)/(\d+)", value.strip())
    if not m:
        raise argparse.ArgumentTypeError(f"shard must look like N/M, got {value!r}")
    n, total = int(m.group(1)), int(m.group(2))
    if not 1 <= n <= total:
        raise argparse.ArgumentTypeError(f"shard needs 1 <= N <= M, got {value!r}")
    return n, total


def select_shard(labels: list[dict], shard: tuple[int, int] | None) -> list[tuple[int, dict]]:
    """(original index, label) pairs for this shard; every alert lands in exactly one."""
    indexed = list(enumerate(labels))
    if shard is None:
        return indexed
    n, total = shard
    return [(i, label) for i, label in indexed if i % total == n - 1]


def configure_environment(cfg: DatasetConfig, cassette_dir: Path) -> None:
    """Point the cassette store and the auth-log tool at this dataset's files."""
    os.environ["ASTRA_CASSETTE_DIR"] = str(cassette_dir)  # read per call by cassette()
    if cfg.auth_log_path is not None:
        os.environ["ASTRA_AUTH_LOG_PATH"] = str(cfg.auth_log_path)
        auth_logs._logs_cache = None  # the loaded fixture is cached per process


def run_and_score(alert: str, expected: dict) -> dict:
    result = graph_triage(alert)
    assert "investigation" in result, "result requires investigation."
    inv = result.get("investigation")  # may be None if guardrail quarantine path
    routing = result.get("routing")  # may be None if guardrail flagged before routing
    predicted = {
        "routing": routing.model_dump() if routing else None,
        "investigation": inv.model_dump() if inv else None,
        "workers_run": result.get("workers_run", []),
        # High/critical incidents pause at escalation_approval (interrupt) for an operator
        # decision the eval never gives, so `escalated` is only set after approval. The
        # pending approval is the system's escalation decision, so count it.
        "escalated": bool(result.get("escalated")) or "__interrupt__" in result,
        "guardrail_flagged": result.get("guardrail_flagged", False),  # for debugging
    }
    # Local stand-ins for LangSmith objects; only .outputs is read by the evaluators.
    # Newer langsmith validates ids as UUIDs and requires name/start_time.
    run_id = uuid.uuid4()
    run_obj = Run(
        id=run_id,
        trace_id=run_id,
        name="graph_triage",
        start_time=datetime.now(UTC),
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


def bootstrap_ci(
    values: list[float], resamples: int = 2000, seed: int = 0
) -> tuple[float, float]:
    """95% percentile-bootstrap interval of the mean. Seeded, so reports are reproducible."""
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(values)
    means = sorted(sum(rng.choices(values, k=n)) / n for _ in range(resamples))
    return (means[int(0.025 * resamples)], means[int(0.975 * resamples) - 1])


def summarize(rows: list[dict]) -> dict:
    """Means, intervals, a per-class breakdown and the routing confusion matrix.

    Each row: {"expected_routing", "predicted_routing", "scores": {metric: float}}.
    Crashed alerts are rows with zero scores, so they count against every metric.
    """

    def stats(subset: list[dict]) -> dict:
        out: dict = {"n": len(subset)}
        for key in METRICS:
            vals = [r["scores"][key] for r in subset if key in r["scores"]]
            if vals:
                lo, hi = bootstrap_ci(vals)
                out[key] = {"mean": sum(vals) / len(vals), "ci95": [lo, hi]}
        return out

    overall = stats(rows)
    per_class = {
        cls: stats([r for r in rows if r["expected_routing"] == cls])
        for cls in sorted({r["expected_routing"] for r in rows})
    }
    confusion: dict[str, dict[str, int]] = {}
    for r in rows:
        row = confusion.setdefault(r["expected_routing"], {})
        pred = r["predicted_routing"] or "null"
        row[pred] = row.get(pred, 0) + 1
    return {"overall": overall, "per_class": per_class, "routing_confusion": confusion}


def _predicted_routing(outcome: dict) -> str | None:
    routing = outcome["predicted"].get("routing") or {}
    cls = routing.get("alert_class")
    return getattr(cls, "value", cls)


def _shard_suffixed(path: Path, shard: tuple[int, int] | None) -> Path:
    if shard is None:
        return path
    n, total = shard
    return path.with_name(f"{path.stem}.shard{n}of{total}{path.suffix}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--mode", choices=("replay", "record", "live"), default="replay")
    parser.add_argument("--dataset", choices=sorted(DATASETS), default="golden")
    parser.add_argument("--cassette-dir", type=Path, help="override the dataset's cassettes")
    parser.add_argument("--report", type=Path, help="override the dataset's report path")
    parser.add_argument("--shard", type=parse_shard, help="run only part N of M, e.g. 1/3")
    parser.add_argument(
        "--no-gate", action="store_true", help="report threshold misses but exit 0"
    )
    args = parser.parse_args(argv)

    cfg = DATASETS[args.dataset]
    cassette_dir = args.cassette_dir or cfg.cassette_dir
    report_path = args.report or _shard_suffixed(cfg.report, args.shard)
    thresholds = cfg.thresholds
    gated = bool(thresholds) and not args.no_gate and args.shard is None

    if not cfg.labels.exists():
        if args.mode == "replay":
            print(f"::warning::Dataset {args.dataset!r} not found at {cfg.labels} — skipping.")
            return
        print(f"::error::Dataset {args.dataset!r} not found at {cfg.labels}")
        sys.exit(EXIT_CONFIG)
    if cfg.auth_log_path is not None and not cfg.auth_log_path.exists():
        print(f"::error::Auth-log fixture for {args.dataset!r} not found at {cfg.auth_log_path}")
        sys.exit(EXIT_CONFIG)

    configure_environment(cfg, cassette_dir)
    labels = json.loads(cfg.labels.read_text())
    selected = select_shard(labels, args.shard)

    if args.mode == "replay" and not any(cassette_dir.glob("eval-*.json")):
        print(
            f"::warning::No recorded cassettes in {cassette_dir}/ yet — skipping the eval. "
            "Run the 'Record eval cassettes' workflow to create them."
        )
        return

    shard_note = f", shard {args.shard[0]}/{args.shard[1]}" if args.shard else ""
    print(f"Dataset {args.dataset}: {len(selected)} of {len(labels)} alerts{shard_note}")

    per_example = []
    rows: list[dict] = []
    failures_by_alert = []
    replay_misses = []

    for pos, (i, label) in enumerate(selected):
        print(
            f"[{pos+1}/{len(selected)}] {label['expected_routing']} ...",
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
            predicted_routing = _predicted_routing(outcome)
            per_example.append(
                {
                    "index": i,
                    "expected_routing": label["expected_routing"],
                    "predicted_routing": predicted_routing,
                    **outcome,
                }
            )
            rows.append(
                {
                    "expected_routing": label["expected_routing"],
                    "predicted_routing": predicted_routing,
                    "scores": {s["key"]: s["score"] for s in outcome["scores"]},
                }
            )
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
            # Zeros for every metric so a crash counts against the scores.
            rows.append(
                {
                    "expected_routing": label["expected_routing"],
                    "predicted_routing": None,
                    "scores": {key: 0.0 for key in METRICS},
                }
            )

    if replay_misses:
        print(
            f"\n::error::{len(replay_misses)} of {len(selected)} alert(s) made requests that "
            "are not in the recorded cassettes, so prompts, tool output or graph logic "
            "changed since recording. Re-record with the 'Record eval cassettes' workflow "
            "and commit the result."
        )
        for m in replay_misses:
            print(f"  [{m['index']+1}] {m['alert_preview'][:80]}")
        sys.exit(EXIT_REPLAY_MISS)

    summary = summarize(rows)
    means = {k: v["mean"] for k, v in summary["overall"].items() if isinstance(v, dict)}
    failures = [k for k, v in means.items() if k in thresholds and v < thresholds[k]]

    report = {
        "dataset": args.dataset,
        "mode": args.mode,
        "shard": list(args.shard) if args.shard else None,
        "gated": gated,
        "aggregates": means,
        "confidence_intervals": {
            k: v["ci95"] for k, v in summary["overall"].items() if isinstance(v, dict)
        },
        "per_class": summary["per_class"],
        "routing_confusion": summary["routing_confusion"],
        "thresholds": thresholds,
        "threshold_failures": failures,
        "per_example": per_example,
        "crashed_examples": failures_by_alert,
        "dataset_size": len(labels),
        "total_examples": len(selected),
        "successful_examples": len(selected) - len(failures_by_alert),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, default=str))

    print("\n=== Scorecard ===")
    for k, v in means.items():
        lo, hi = summary["overall"][k]["ci95"]
        if k in thresholds:
            status = "✓" if v >= thresholds[k] else "✗"
            limit = f"threshold: {thresholds[k]:.0%}"
        else:
            status, limit = "·", "no threshold"
        print(f"  {status} {k}: {v:.2%}  (95% CI {lo:.0%}–{hi:.0%}; {limit})")

    print("\n=== Per routing class (mean) ===")
    short = {k: k.removesuffix("_correctness") for k in METRICS}
    print("  " + f"{'class':<15}{'n':>4}" + "".join(f"{short[k]:>12}" for k in METRICS))
    for cls, st in summary["per_class"].items():
        cells = "".join(
            f"{st[k]['mean']:>12.0%}" if k in st else f"{'-':>12}" for k in METRICS
        )
        print(f"  {cls:<15}{st['n']:>4}{cells}")
    print(f"\nReport: {report_path}")

    if failures_by_alert:
        print(
            f"\n⚠ {len(failures_by_alert)} alert(s) crashed — see 'crashed_examples' in the report"
        )
        for f in failures_by_alert:
            print(f"  [{f['index']+1}] {f['error_type']}: {f['error_message'][:80]}")
    if failures:
        if gated:
            print(f"\n❌ REGRESSION on: {failures}")
            sys.exit(EXIT_REGRESSION)
        print(f"\n⚠ Below threshold on {failures} (not gated for this run)")
        return
    if thresholds:
        print("\n✓ All metrics above threshold" + ("" if gated else " (not gated for this run)"))


if __name__ == "__main__":
    main()
