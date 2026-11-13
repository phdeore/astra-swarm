"""query_auth_logs measures lookback windows from the fixture's clock, not the wall clock."""

from __future__ import annotations

import json

import pytest

from astra_swarm import auth_logs

LOGS = [
    {"ts": "2026-09-14T08:00:00Z", "user": "alice@example.com", "src_ip": "1.1.1.1",
     "geo": "US", "result": "success", "mfa_challenge": False},
    {"ts": "2026-09-15T07:00:00Z", "user": "alice@example.com", "src_ip": "2.2.2.2",
     "geo": "RU", "result": "fail", "mfa_challenge": True},
    {"ts": "2026-09-15T08:00:00Z", "user": "bob@example.com", "src_ip": "3.3.3.3",
     "geo": "US", "result": "success", "mfa_challenge": False},
]


@pytest.fixture
def fixture_logs(monkeypatch, tmp_path):
    path = tmp_path / "auth_logs.json"
    path.write_text(json.dumps(LOGS))
    monkeypatch.setenv("ASTRA_AUTH_LOG_PATH", str(path))
    monkeypatch.delenv("ASTRA_AUTH_LOG_REFERENCE_TIME", raising=False)
    monkeypatch.setattr(auth_logs, "_logs_cache", None)
    return path


def test_window_is_relative_to_newest_log_entry(fixture_logs):
    # Newest entry is 2026-09-15T08:00Z; a 2-hour window keeps only alice's 07:00 login.
    result = auth_logs.query_auth_logs("alice@example.com", hours=2)
    assert result["login_count"] == 1
    assert result["unique_geos"] == ["RU"]

    full = auth_logs.query_auth_logs("alice@example.com", hours=336)
    assert full["login_count"] == 2
    assert full["failure_count"] == 1
    assert full["mfa_challenges"] == 1


def test_reference_time_override(fixture_logs, monkeypatch):
    monkeypatch.setenv("ASTRA_AUTH_LOG_REFERENCE_TIME", "2026-09-14T09:00:00Z")
    result = auth_logs.query_auth_logs("alice@example.com", hours=2)
    assert result["login_count"] == 1
    assert result["unique_geos"] == ["US"]


def test_unknown_user(fixture_logs):
    assert auth_logs.query_auth_logs("nobody@example.com", hours=336)["note"] == (
        "no activity in window"
    )


def test_bundled_fixture_is_found_without_env(monkeypatch):
    """The default path must resolve inside the repo (it used to point at Colab's /content)."""
    monkeypatch.delenv("ASTRA_AUTH_LOG_PATH", raising=False)
    monkeypatch.delenv("ASTRA_AUTH_LOG_REFERENCE_TIME", raising=False)
    monkeypatch.setattr(auth_logs, "_logs_cache", None)
    assert auth_logs._log_path().exists()
    users = {entry["user"] for entry in auth_logs._load()}
    some_user = sorted(users)[0]
    assert auth_logs.query_auth_logs(some_user, hours=336)["login_count"] >= 1
