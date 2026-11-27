"""scripts/run_eval.py: dataset selection, sharding, summaries and gating — no API calls."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from astra_swarm import auth_logs

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_eval.py"
_spec = importlib.util.spec_from_file_location("run_eval", _SCRIPT)
run_eval = importlib.util.module_from_spec(_spec)
sys.modules["run_eval"] = run_eval  # dataclasses look their module up while executing
_spec.loader.exec_module(run_eval)  # type: ignore[union-attr]


@pytest.fixture(autouse=True)
def _restore_process_state(monkeypatch):
    """main()/configure_environment() write os.environ and the auth-log cache directly;
    registering them with monkeypatch restores the originals after each test."""
    for var in ("ASTRA_CASSETTE_DIR", "ASTRA_AUTH_LOG_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(auth_logs, "_logs_cache", None)


# --- configuration --------------------------------------------------------------------


def test_golden_defaults_are_unchanged():
    """The PR gate and the committed cassettes depend on these exact values."""
    golden = run_eval.DATASETS["golden"]
    assert golden.labels == Path("evals/week5_golden_set.json")
    assert golden.cassette_dir == Path("evals/cassettes")
    assert golden.report == Path("eval_report.json")
    assert golden.thresholds == run_eval.THRESHOLDS
    assert golden.auth_log_path is None


def test_real_world_is_isolated_from_golden():
    golden, real = run_eval.DATASETS["golden"], run_eval.DATASETS["real_world"]
    assert real.cassette_dir != golden.cassette_dir
    assert real.report != golden.report
    assert real.auth_log_path is not None  # never the shared synthetic fixture
    assert real.thresholds == {}  # report only until a baseline exists


def test_configure_environment_sets_paths_and_resets_auth_cache(monkeypatch, tmp_path):
    monkeypatch.delenv("ASTRA_AUTH_LOG_PATH", raising=False)
    monkeypatch.setattr(auth_logs, "_logs_cache", [{"stale": True}])
    cfg = run_eval.DatasetConfig(
        labels=tmp_path / "set.json",
        cassette_dir=tmp_path / "cassettes",
        report=tmp_path / "report.json",
        auth_log_path=tmp_path / "auth.json",
    )
    run_eval.configure_environment(cfg, cfg.cassette_dir)
    assert run_eval.os.environ["ASTRA_CASSETTE_DIR"] == str(cfg.cassette_dir)
    assert run_eval.os.environ["ASTRA_AUTH_LOG_PATH"] == str(cfg.auth_log_path)
    assert auth_logs._logs_cache is None


def test_configure_environment_leaves_auth_logs_alone_for_golden(monkeypatch, tmp_path):
    monkeypatch.delenv("ASTRA_AUTH_LOG_PATH", raising=False)
    cached = [{"kept": True}]
    monkeypatch.setattr(auth_logs, "_logs_cache", cached)
    run_eval.configure_environment(run_eval.DATASETS["golden"], tmp_path)
    assert "ASTRA_AUTH_LOG_PATH" not in run_eval.os.environ
    assert auth_logs._logs_cache is cached


# --- sharding -------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [("1/1", (1, 1)), ("2/3", (2, 3)), (" 3/3 ", (3, 3))])
def test_parse_shard(value, expected):
    assert run_eval.parse_shard(value) == expected


@pytest.mark.parametrize("value", ["0/2", "3/2", "1", "a/b", "1/0", "-1/2"])
def test_parse_shard_rejects(value):
    with pytest.raises(run_eval.argparse.ArgumentTypeError):
        run_eval.parse_shard(value)


@pytest.mark.parametrize("total", [1, 2, 3, 7])
def test_shards_cover_every_alert_exactly_once(total):
    labels = [{"alert": str(i)} for i in range(20)]
    seen = [i for n in range(1, total + 1) for i, _ in run_eval.select_shard(labels, (n, total))]
    assert sorted(seen) == list(range(20))


def test_no_shard_keeps_order():
    labels = [{"alert": "a"}, {"alert": "b"}]
    assert run_eval.select_shard(labels, None) == [(0, labels[0]), (1, labels[1])]


def test_shard_report_name():
    path = Path("evals/real_world_report.json")
    assert run_eval._shard_suffixed(path, None) == path
    assert run_eval._shard_suffixed(path, (2, 3)).name == "real_world_report.shard2of3.json"


# --- statistics -----------------------------------------------------------------------


def test_bootstrap_ci_is_deterministic_and_bounded():
    vals = [1.0] * 15 + [0.0] * 5
    lo, hi = run_eval.bootstrap_ci(vals)
    assert (lo, hi) == run_eval.bootstrap_ci(vals)
    assert 0.0 <= lo <= 0.75 <= hi <= 1.0
    assert run_eval.bootstrap_ci([1.0] * 10) == (1.0, 1.0)
    assert run_eval.bootstrap_ci([]) == (0.0, 0.0)


def _row(expected, predicted, score):
    return {
        "expected_routing": expected,
        "predicted_routing": predicted,
        "scores": {k: score for k in run_eval.METRICS},
    }


def test_summarize_per_class_and_confusion():
    rows = [
        _row("malware", "malware", 1.0),
        _row("malware", "network", 0.0),
        _row("network", None, 0.0),  # crashed or quarantined
    ]
    s = run_eval.summarize(rows)
    assert s["overall"]["n"] == 3
    assert s["overall"]["routing_correctness"]["mean"] == pytest.approx(1 / 3)
    assert s["per_class"]["malware"]["n"] == 2
    assert s["per_class"]["malware"]["routing_correctness"]["mean"] == 0.5
    assert s["per_class"]["network"]["routing_correctness"]["mean"] == 0.0
    assert s["routing_confusion"] == {
        "malware": {"malware": 1, "network": 1},
        "network": {"null": 1},
    }


# --- end to end with a fake graph -----------------------------------------------------


class _Dumpable:
    def __init__(self, data):
        self._data = data

    def model_dump(self):
        return self._data


def _fake_graph(state_by_alert):
    def fake(alert):
        return state_by_alert[alert]

    return fake


@pytest.fixture
def tiny_dataset(monkeypatch, tmp_path):
    labels = [
        {
            "alert": "alert-ok",
            "expected_routing": "malware",
            "expected_severity": "high",
            "expected_escalation": True,
            "expected_workers_contains": ["enrichment"],
        },
        {
            "alert": "alert-wrong",
            "expected_routing": "network",
            "expected_severity": "low",
            "expected_escalation": False,
            "expected_workers_contains": ["enrichment"],
        },
    ]
    (tmp_path / "set.json").write_text(json.dumps(labels))
    states = {
        "alert-ok": {
            "routing": _Dumpable({"alert_class": "malware"}),
            "investigation": _Dumpable({"severity": "high"}),
            "workers_run": ["enrichment", "assessment"],
            "__interrupt__": [object()],
        },
        "alert-wrong": {
            "routing": _Dumpable({"alert_class": "malware"}),
            "investigation": _Dumpable({"severity": "critical"}),
            "workers_run": ["enrichment", "assessment"],
            "escalated": True,
        },
    }
    monkeypatch.setattr(run_eval, "graph_triage", _fake_graph(states))
    monkeypatch.delenv("ASTRA_AUTH_LOG_PATH", raising=False)

    def make(thresholds):
        cfg = run_eval.DatasetConfig(
            labels=tmp_path / "set.json",
            cassette_dir=tmp_path / "cassettes",
            report=tmp_path / "report.json",
            thresholds=thresholds,
        )
        monkeypatch.setitem(run_eval.DATASETS, "tiny", cfg)
        return cfg

    return make


def test_main_writes_report_with_breakdown(tiny_dataset):
    cfg = tiny_dataset({})
    run_eval.main(["--dataset", "tiny", "--mode", "live"])
    report = json.loads(cfg.report.read_text())
    assert report["dataset"] == "tiny"
    assert report["gated"] is False
    assert report["aggregates"]["routing_correctness"] == 0.5
    assert report["routing_confusion"] == {"malware": {"malware": 1}, "network": {"malware": 1}}
    assert report["per_class"]["network"]["escalation_correctness"]["mean"] == 0.0
    assert [e["index"] for e in report["per_example"]] == [0, 1]


def test_main_gates_on_regression(tiny_dataset):
    tiny_dataset({"routing_correctness": 0.9})
    with pytest.raises(SystemExit) as exc:
        run_eval.main(["--dataset", "tiny", "--mode", "live"])
    assert exc.value.code == run_eval.EXIT_REGRESSION


@pytest.mark.parametrize("extra", [["--no-gate"], ["--shard", "1/1"]])
def test_no_gate_and_shards_report_without_failing(tiny_dataset, extra):
    tiny_dataset({"routing_correctness": 0.9})
    run_eval.main(["--dataset", "tiny", "--mode", "live", *extra])  # no SystemExit


def test_replay_without_cassettes_skips(tiny_dataset, capsys):
    cfg = tiny_dataset({})
    run_eval.main(["--dataset", "tiny", "--mode", "replay"])
    assert "No recorded cassettes" in capsys.readouterr().out
    assert not cfg.report.exists()


def test_missing_dataset_is_a_config_error_outside_replay(monkeypatch, tmp_path):
    cfg = run_eval.DatasetConfig(
        labels=tmp_path / "absent.json", cassette_dir=tmp_path, report=tmp_path / "r.json"
    )
    monkeypatch.setitem(run_eval.DATASETS, "absent", cfg)
    run_eval.main(["--dataset", "absent", "--mode", "replay"])  # warns, exits 0
    with pytest.raises(SystemExit) as exc:
        run_eval.main(["--dataset", "absent", "--mode", "record"])
    assert exc.value.code == run_eval.EXIT_CONFIG
