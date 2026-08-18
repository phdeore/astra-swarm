"""Deterministic replay of Anthropic API calls, for iterating without spending tokens.

Usage:
    from astra_swarm.cassette import cassette
    with cassette("day05_alert3", mode="record"):
        result = triage_chain(alert)   # real API calls, responses saved to disk

    with cassette("day05_alert3", mode="replay"):
        result = triage_chain(alert)   # zero API calls; identical responses

    with cassette("day05_alert3", mode="auto"):
        result = triage_chain(alert)   # replay if cassette exists, else record
"""

from __future__ import annotations

import hashlib
import json
import pickle
from contextlib import contextmanager
from pathlib import Path

from anthropic import Anthropic

_CASSETTE_DIR = Path("./cassettes")  # or ./cassettes on Mac
_original_create = Anthropic().messages.create.__func__  # unbound method


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
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


@contextmanager
def cassette(name: str, mode: str = "auto"):
    """Wrap a block of code to record or replay Anthropic API responses.

    mode: 'record' always calls real API + saves; 'replay' only replays (errors on miss);
          'auto' replays if cache exists, records if not.
    """
    _CASSETTE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _CASSETTE_DIR / f"{name}.pkl"
    cache: dict[str, object] = {}
    if cache_path.exists() and mode in ("replay", "auto"):
        cache = pickle.loads(cache_path.read_bytes())

    from types import MethodType

    def _wrapped(self, **kwargs):
        fp = _fingerprint(kwargs)
        if fp in cache and mode in ("replay", "auto"):
            return cache[fp]
        if mode == "replay":
            raise RuntimeError(
                f"cassette miss for {name!r} in replay mode; fingerprint={fp}. "
                "Rerun in 'record' or 'auto' mode."
            )
        response = _original_create(self, **kwargs)
        cache[fp] = response
        cache_path.write_bytes(pickle.dumps(cache))
        return response

    # Monkeypatch every Anthropic client instance's create method for the block
    Anthropic.messages.__class__.create = _wrapped  # type: ignore[assignment]
    try:
        yield
    finally:
        # Restore the original method
        Anthropic.messages.__class__.create = _original_create  # type: ignore[assignment]
