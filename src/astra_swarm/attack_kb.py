"""Astra-Swarm MITRE ATT&CK knowledge base — Day 4.

Loads the Enterprise ATT&CK STIX 2.1 bundle and exposes:
  - lookup_by_id(technique_id)
  - search_by_keyword(keyword, limit=5)

The bundle is ~55 MB. First call downloads and caches it on disk; subsequent calls
in the same process are in-memory.

The bundle is pinned to a tagged ATT&CK release and verified by SHA-256, so tool
results are reproducible (recorded eval cassettes depend on this) and a tampered or
changed download is rejected. To upgrade: bump _ATTACK_VERSION, update
_ATTACK_SHA256, and re-record the eval cassettes.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

_ATTACK_VERSION = "20.0"
_ATTACK_SHA256 = "2339a3c36353d5ee2c07e98af3fafbf00761e0e3979ede06402657445b7b4278"
_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"v{_ATTACK_VERSION}/enterprise-attack/enterprise-attack-{_ATTACK_VERSION}.json"
)

# In-process caches — built once per Python session.
_tech_by_id: dict[str, dict] | None = None
_tactic_by_shortname: dict[str, str] | None = None


def _cache_path() -> Path:
    """Versioned on-disk cache; directory overridable via ASTRA_ATTACK_CACHE_DIR."""
    cache_dir = Path(os.environ.get("ASTRA_ATTACK_CACHE_DIR", tempfile.gettempdir()))
    return cache_dir / f"astra_swarm_enterprise_attack_{_ATTACK_VERSION}.json"


def _verified(data: bytes) -> bool:
    return hashlib.sha256(data).hexdigest() == _ATTACK_SHA256


def _download_bundle() -> dict:
    cache_path = _cache_path()
    if cache_path.exists():
        data = cache_path.read_bytes()
        if _verified(data):
            return json.loads(data)
        print(f"[attack_kb] cached bundle at {cache_path} failed checksum; re-downloading")
    print(f"[attack_kb] fetching enterprise-attack STIX bundle v{_ATTACK_VERSION}...")
    with urllib.request.urlopen(_STIX_URL, timeout=120) as r:
        data = r.read()
    if not _verified(data):
        raise RuntimeError(
            f"ATT&CK bundle v{_ATTACK_VERSION} failed SHA-256 verification; refusing to use it"
        )
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(data)
    print(f"[attack_kb] cached {len(data) / 1_048_576:.1f} MB at {cache_path}")
    return json.loads(data)


def _load() -> tuple[dict[str, dict], dict[str, str]]:
    """Build id→technique and shortname→tactic-name indexes."""
    global _tech_by_id, _tactic_by_shortname
    if _tech_by_id is not None:
        return _tech_by_id, _tactic_by_shortname  # type: ignore[return-value]

    bundle = (
        _download_bundle()
    )  # TODO: Memory usage: ~30 MB for the bundle, ~10 MB for the indexes
    tech_by_id: dict[str, dict] = {}
    tactic_by_shortname: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        t = obj.get("type")
        if t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id", "")
                    if tid.startswith("T"):
                        tech_by_id[tid] = obj
                    break
        elif t == "x-mitre-tactic":
            sn = obj.get("x_mitre_shortname")
            if sn:
                tactic_by_shortname[sn] = obj.get("name", sn)

    _tech_by_id, _tactic_by_shortname = tech_by_id, tactic_by_shortname
    print(
        f"[attack_kb] indexed {len(tech_by_id)} techniques, "
        f"{len(tactic_by_shortname)} tactics"
    )
    return tech_by_id, tactic_by_shortname


def _compact(obj: dict, tactic_map: dict[str, str]) -> dict[str, Any]:
    """Squeeze a STIX attack-pattern into the compact shape our tool returns."""
    tid, url = "", ""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            tid = ref.get("external_id", "")
            url = ref.get("url", "")
            break

    tactics = [
        tactic_map.get(p.get("phase_name", ""), p.get("phase_name", ""))
        for p in obj.get("kill_chain_phases", [])
        if p.get("kill_chain_name") == "mitre-attack"
    ]

    desc = obj.get("description", "")
    if len(desc) > 1500:
        desc = desc[:1500] + " …[truncated]"

    return {
        "id": tid,
        "name": obj.get("name", ""),
        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        "tactics": tactics,
        "platforms": obj.get("x_mitre_platforms", []),
        "data_sources": obj.get("x_mitre_data_sources", []),
        "description": desc,
        "url": url,
    }


def lookup_by_id(technique_id: str) -> dict[str, Any]:
    """Exact-match lookup by Txxxx or Txxxx.yyy ID (case-insensitive)."""
    tech_by_id, tactic_map = _load()
    tid = technique_id.strip().upper()
    obj = tech_by_id.get(tid)
    if not obj:
        return {"id": tid, "error": f"Technique {tid} not in Enterprise ATT&CK."}
    return _compact(obj, tactic_map)


def search_by_keyword(keyword: str, limit: int = 5) -> list[dict[str, Any]]:
    """Cheap ranker: exact-name > name-contains > description-contains."""
    tech_by_id, tactic_map = _load()
    kw = keyword.strip().lower()
    if not kw:
        return []

    scored: list[tuple[int, dict]] = []
    for obj in tech_by_id.values():
        name = obj.get("name", "").lower()
        desc = obj.get("description", "").lower()
        if kw == name:
            score = 100
        elif kw in name:
            score = 80
        elif kw in desc:
            score = 20
        else:
            continue
        scored.append((score, obj))

    scored.sort(key=lambda x: -x[0])
    return [_compact(o, tactic_map) for _, o in scored[:limit]]
