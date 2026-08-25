"""Astra-Swarm identity signal tool — query synthetic auth logs."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _log_path() -> Path:
    """Lazy-resolved to honor an env var override (matches cassette pattern)."""
    return Path(
        os.environ.get(
            "ASTRA_AUTH_LOG_PATH",
            "/content/astra-swarm/data/synthetic/auth_logs.json",
        )
    )


_logs_cache: list[dict] | None = None


def _load() -> list[dict]:
    global _logs_cache
    if _logs_cache is None:
        _logs_cache = json.loads(_log_path().read_text())
    assert _logs_cache is not None
    return _logs_cache


def query_auth_logs(user: str, hours: int = 24) -> dict[str, Any]:
    """Return recent authentication activity for a user."""
    logs = _load()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    def _within(ts: str) -> bool:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")) >= cutoff
        except ValueError:
            return False

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
