"""Astra-Swarm identity signal tool — query synthetic auth logs."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Repo layout: <root>/src/astra_swarm/auth_logs.py -> <root>/data/synthetic/auth_logs.json
_DEFAULT_LOG_PATH = Path(__file__).resolve().parents[2] / "data" / "synthetic" / "auth_logs.json"


def _log_path() -> Path:
    """Lazy-resolved so ASTRA_AUTH_LOG_PATH can override the bundled fixture."""
    return Path(os.environ.get("ASTRA_AUTH_LOG_PATH", str(_DEFAULT_LOG_PATH)))


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


_logs_cache: list[dict] | None = None


def _load() -> list[dict]:
    global _logs_cache
    if _logs_cache is None:
        _logs_cache = json.loads(_log_path().read_text())
    assert _logs_cache is not None
    return _logs_cache


def _reference_time(logs: list[dict]) -> datetime:
    """The 'now' that lookback windows are measured from.

    The logs are a static fixture, so measuring from the wall clock makes every query
    drift to "no activity" as the fixture ages (and makes recorded evals
    non-reproducible). Use ASTRA_AUTH_LOG_REFERENCE_TIME if set (ISO-8601), otherwise
    the newest timestamp in the log file.
    """
    override = os.environ.get("ASTRA_AUTH_LOG_REFERENCE_TIME")
    if override:
        ref = _parse_ts(override)
        if ref is None:
            raise ValueError(f"ASTRA_AUTH_LOG_REFERENCE_TIME is not ISO-8601: {override!r}")
        return ref
    stamps = [t for t in (_parse_ts(l.get("ts", "")) for l in logs) if t is not None]
    if not stamps:
        raise ValueError(f"no parseable timestamps in {_log_path()}")
    return max(stamps)


def query_auth_logs(user: str, hours: int = 24) -> dict[str, Any]:
    """Return authentication activity for a user in the `hours` before the reference time."""
    logs = _load()
    reference = _reference_time(logs)
    cutoff = reference - timedelta(hours=hours)

    def _within(ts: str) -> bool:
        parsed = _parse_ts(ts)
        return parsed is not None and cutoff <= parsed <= reference

    user_logs = [l for l in logs if l["user"] == user and _within(l["ts"])]
    if not user_logs:
        return {
            "user": user,
            "hours": hours,
            "entries": [],
            "note": "no activity in window",
        }

    unique_ips = sorted({l["src_ip"] for l in user_logs})
    unique_geos = sorted({l["geo"] for l in user_logs})
    failures = [l for l in user_logs if l["result"] == "fail"]
    mfa_count = sum(1 for l in user_logs if l.get("mfa_challenge"))
    return {
        "user": user,
        "hours": hours,
        "login_count": len(user_logs),
        "success_count": len(user_logs) - len(failures),
        "failure_count": len(failures),
        "unique_ips": unique_ips,
        "unique_geos": unique_geos,
        "mfa_challenges": mfa_count,
        "recent_entries": user_logs[:10],
    }
