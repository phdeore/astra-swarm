"""The ATT&CK bundle is pinned and checksum-verified."""

from __future__ import annotations

import pytest

from astra_swarm import attack_kb


def test_url_is_pinned_to_a_release_tag():
    assert "/master/" not in attack_kb._STIX_URL
    assert f"/v{attack_kb._ATTACK_VERSION}/" in attack_kb._STIX_URL


def test_tampered_cache_is_not_trusted(monkeypatch, tmp_path):
    monkeypatch.setenv("ASTRA_ATTACK_CACHE_DIR", str(tmp_path))
    attack_kb._cache_path().write_bytes(b'{"objects": []}')  # wrong checksum

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"objects": ["tampered download"]}'

    monkeypatch.setattr(attack_kb.urllib.request, "urlopen", lambda *a, **k: _Resp())
    with pytest.raises(RuntimeError, match="SHA-256"):
        attack_kb._download_bundle()
