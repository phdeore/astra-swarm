"""Cassette record/replay without touching the network."""

from __future__ import annotations

import json

import pytest
from anthropic import Anthropic
from anthropic.types import Message

from astra_swarm import cassette as cassette_mod
from astra_swarm.cassette import CassetteMiss, cassette

REQUEST = {
    "model": "claude-haiku-4-5-20251001",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "hi"}],
}


def _fake_message(text: str) -> Message:
    return Message.model_validate(
        {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": REQUEST["model"],
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 3, "output_tokens": 2},
        }
    )


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ASTRA_CASSETTE_DIR", str(tmp_path))
    calls = []

    def fake_create(self, **kwargs):
        calls.append(kwargs)
        return _fake_message("recorded answer")

    monkeypatch.setattr(cassette_mod, "_original_create", fake_create)
    c = Anthropic(api_key="test-key-not-used")
    c.calls = calls  # type: ignore[attr-defined]
    return c


def test_record_then_replay_round_trips_as_json(client, tmp_path):
    with cassette("demo", mode="record"):
        live = client.messages.create(**REQUEST)
    assert len(client.calls) == 1

    path = tmp_path / "demo.json"
    assert path.exists()
    json.loads(path.read_text())  # plain JSON, not pickle

    with cassette("demo", mode="replay"):
        replayed = client.messages.create(**REQUEST)
    assert len(client.calls) == 1  # no new API call
    assert replayed.content[0].text == live.content[0].text == "recorded answer"


def test_replay_miss_raises(client):
    with cassette("demo", mode="record"):
        client.messages.create(**REQUEST)
    changed = {**REQUEST, "messages": [{"role": "user", "content": "different prompt"}]}
    with pytest.raises(CassetteMiss), cassette("demo", mode="replay"):
        client.messages.create(**changed)


def test_replay_without_any_cassette_raises(client):
    with pytest.raises(CassetteMiss), cassette("never-recorded", mode="replay"):
        client.messages.create(**REQUEST)


def test_fingerprint_stable_for_replayed_content_blocks():
    """A follow-up request built from a live response must fingerprint the same as one
    built from the replayed (JSON round-tripped) response, or multi-turn replay breaks."""
    live = _fake_message("x")
    replayed = Message.model_validate(json.loads(json.dumps(live.model_dump(mode="json"))))

    def follow_up(msg: Message) -> dict:
        return {
            **REQUEST,
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": msg.content},
                {"role": "user", "content": "next"},
            ],
        }

    assert cassette_mod._fingerprint(follow_up(live)) == cassette_mod._fingerprint(
        follow_up(replayed)
    )


def test_invalid_mode_rejected():
    with pytest.raises(ValueError), cassette("x", mode="bogus"):
        pass
