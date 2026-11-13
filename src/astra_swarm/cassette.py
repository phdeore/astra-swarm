"""Deterministic replay of Anthropic API calls, for iterating without spending tokens.

Usage:
    from astra_swarm.cassette import cassette
    with cassette("day05_alert3", mode="record"):
        result = triage_chain(alert)   # real API calls, responses saved to disk

    with cassette("day05_alert3", mode="replay"):
        result = triage_chain(alert)   # zero API calls; identical responses

    with cassette("day05_alert3", mode="auto"):
        result = triage_chain(alert)   # replay if cassette exists, else record

Cassettes are plain JSON ({fingerprint: Message as JSON}), never pickle: they are
committed to the repo and loaded in CI, so a cassette from an untrusted pull
request must not be able to execute code when it is read.
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from anthropic.resources.messages import Messages
from anthropic.types import Message

MODES = ("record", "replay", "auto")


class CassetteMiss(RuntimeError):
    """Replay mode found no recorded response for a request."""


def _cassette_dir() -> Path:
    return Path(os.environ.get("ASTRA_CASSETTE_DIR", "cassettes"))


_original_create = Messages.create


def _normalize(obj: Any) -> Any:
    """JSON-encode SDK/Pydantic objects by value (not repr) so fingerprints are stable."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", exclude_none=True)
    return str(obj)


def _fingerprint(kwargs: dict) -> str:
    """Stable hash of request kwargs — same request → same fingerprint → same cached response."""
    # We hash the parts that determine the response; skip anything transient.
    payload = {
        "model": kwargs.get("model"),
        "system": kwargs.get("system"),
        "messages": kwargs.get("messages"),
        "tools": kwargs.get("tools"),
        "max_tokens": kwargs.get("max_tokens"),
        "output_config": kwargs.get("output_config"),
    }
    blob = json.dumps(payload, sort_keys=True, default=_normalize).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _load(path: Path) -> dict[str, Message]:
    raw = json.loads(path.read_text())
    return {fp: Message.model_validate(msg) for fp, msg in raw.items()}


def _save(path: Path, cache: dict[str, Message]) -> None:
    data = {fp: msg.model_dump(mode="json") for fp, msg in sorted(cache.items())}
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


@contextmanager
def cassette(name: str, mode: str = "auto"):
    """Wrap a block of code to record or replay Anthropic API responses.

    mode: 'record' always calls real API + saves (replacing the cassette);
          'replay' only replays (raises CassetteMiss on a miss);
          'auto' replays if cached, records if not.
    """
    if mode not in MODES:
        raise ValueError(f"cassette mode must be one of {MODES}, got {mode!r}")
    cache_dir = _cassette_dir()  # resolved every call
    cache_path = cache_dir / f"{name}.json"
    cache: dict[str, Message] = {}
    if cache_path.exists() and mode in ("replay", "auto"):
        cache = _load(cache_path)
    hits = misses = 0

    def _wrapped(self, **kwargs):
        nonlocal hits, misses
        fp = _fingerprint(kwargs)
        if fp in cache and mode in ("replay", "auto"):
            hits += 1
            return cache[fp]
        if mode == "replay":
            raise CassetteMiss(
                f"no recorded response in cassette {name!r} for request fingerprint {fp}"
            )
        misses += 1
        response = _original_create(self, **kwargs)
        cache[fp] = response
        cache_dir.mkdir(parents=True, exist_ok=True)
        _save(cache_path, cache)
        return response

    Messages.create = _wrapped
    try:
        yield
    finally:
        Messages.create = _original_create
    print(f"[cassette:{name}] {hits} replayed, {misses} recorded")
