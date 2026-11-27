"""Condense raw Hayabusa / Suricata output into one record per (dataset, rule).

Run by collect.sh with ``python -I`` on output produced from downloaded, untrusted
logs. It only parses JSON; nothing from the input is executed or used as a path.

    python -I condense.py hayabusa <timeline.jsonl> <dataset> <source> <out_dir>
    python -I condense.py suricata <eve.json>       <dataset> <source> <out_dir>
    python -I condense.py auth     <raw_log_dir>    <dataset> <source> <out_dir>

Appends detections to <out_dir>/detections.jsonl. The ``auth`` mode reads the raw OTRF
Security events (4624/4625/4648/4768/4769/4771/4776) and appends compact logon records
to <out_dir>/auth_events.jsonl for the ITDR auth-log fixture.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MAX_SAMPLES = 3
MAX_FIELD = 300  # characters kept per detail value
MAX_AUTH_PER_DATASET = 400
AUTH_EVENT_IDS = {4624, 4625, 4648, 4768, 4769, 4771, 4776}
_SERVICE_DOMAINS = {"NT AUTHORITY", "Window Manager", "Font Driver Host", "NT SERVICE"}


def _clip(value):
    if isinstance(value, str):
        return value if len(value) <= MAX_FIELD else value[:MAX_FIELD] + "…"
    if isinstance(value, dict):
        return {str(k): _clip(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v) for v in value[:10]]
    return value


def _rows(path: Path):
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _merge(groups: dict, key, base: dict, ts: str, sample: dict) -> None:
    g = groups.get(key)
    if g is None:
        g = groups[key] = {**base, "count": 0, "first_ts": ts, "last_ts": ts, "samples": []}
    g["count"] += 1
    g["first_ts"] = min(g["first_ts"], ts)
    g["last_ts"] = max(g["last_ts"], ts)
    if len(g["samples"]) < MAX_SAMPLES:
        g["samples"].append(sample)


def _raw_auth_record(ev: dict) -> dict | None:
    """A logon record in the shape of data/synthetic/auth_logs.json, from a raw event."""
    if ev.get("Channel") != "Security":
        return None
    try:
        eid = int(ev.get("EventID"))
    except (TypeError, ValueError):
        return None
    if eid not in AUTH_EVENT_IDS:
        return None
    user = str(ev.get("TargetUserName") or "").split("@")[0]
    domain = str(ev.get("TargetDomainName") or "")
    if not user or user in ("-", "ANONYMOUS LOGON") or user.endswith("$") or domain in _SERVICE_DOMAINS:
        return None  # machine/service accounts and empty users carry no identity signal
    src = str(ev.get("IpAddress") or ev.get("Workstation") or "-").removeprefix("::ffff:")
    failed = eid in (4625, 4771) or (eid in (4768, 4769, 4776) and str(ev.get("Status", "0x0")) not in ("0x0", "0"))
    return {
        "ts": ev.get("@timestamp") or ev.get("TimeCreated") or "",
        "user": user,
        "domain": domain,
        "src_ip": src,
        "result": "fail" if failed else "success",
        "event_id": eid,
        "logon_type": ev.get("LogonType"),
        "status": ev.get("Status") or ev.get("FailureReason") or "",
        "computer": ev.get("Hostname") or "",
    }


def condense_auth(root: Path, dataset: str, source: str):
    auth: list[dict] = []
    for f in sorted(root.rglob("*.json")):
        for ev in _rows(f):
            rec = _raw_auth_record(ev)
            if rec is not None:
                auth.append({**rec, "dataset": dataset})
                if len(auth) >= MAX_AUTH_PER_DATASET:
                    return [], auth
    return [], auth


def condense_hayabusa(path: Path, dataset: str, source: str):
    groups: dict = {}
    for row in _rows(path):
        rule_id = row.get("RuleID")
        if not rule_id:
            continue
        base = {
            "tool": "hayabusa",
            "dataset": dataset,
            "source": source,
            "rule_id": rule_id,
            "rule_title": row.get("RuleTitle", ""),
            "rule_file": row.get("RuleFile", ""),
            "rule_author": row.get("RuleAuthor", ""),
            "rule_status": row.get("Status", ""),
            "level": row.get("Level", ""),
            "mitre_tactics": row.get("MitreTactics") or [],
            "mitre_tags": row.get("MitreTags") or [],
            "other_tags": row.get("OtherTags") or [],
            "channel": row.get("Channel", ""),
            "provider": row.get("Provider", ""),
            "event_id": row.get("EventID"),
        }
        sample = {
            "ts": row.get("Timestamp", ""),
            "computer": row.get("Computer", ""),
            "record_id": row.get("RecordID"),
            "details": _clip(row.get("Details") or {}),
        }
        _merge(groups, rule_id, base, sample["ts"], sample)
    return list(groups.values()), []


def condense_suricata(path: Path, dataset: str, source: str):
    groups: dict = {}
    for ev in _rows(path):
        if ev.get("event_type") != "alert":
            continue
        a = ev.get("alert") or {}
        sid = a.get("signature_id")
        if sid is None:
            continue
        base = {
            "tool": "suricata",
            "dataset": dataset,
            "source": source,
            "sid": sid,
            "gid": a.get("gid"),
            "rev": a.get("rev"),
            "signature": a.get("signature", ""),
            "category": a.get("category", ""),
            "severity": a.get("severity"),
            "metadata": _clip(a.get("metadata") or {}),
        }
        sample = {
            "ts": ev.get("timestamp", ""),
            "src_ip": ev.get("src_ip"),
            "src_port": ev.get("src_port"),
            "dest_ip": ev.get("dest_ip"),
            "dest_port": ev.get("dest_port"),
            "proto": ev.get("proto"),
            "app_proto": ev.get("app_proto"),
            "direction": ev.get("direction"),
        }
        for proto in ("http", "tls", "dns", "smb"):
            if proto in ev:
                sample[proto] = _clip(ev[proto])
        _merge(groups, sid, base, sample["ts"], sample)
    return list(groups.values()), []


def _append(path: Path, rows: list[dict]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: list[str]) -> int:
    modes = {"hayabusa": condense_hayabusa, "suricata": condense_suricata, "auth": condense_auth}
    if len(argv) != 5 or argv[0] not in modes:
        print(__doc__, file=sys.stderr)
        return 2
    tool, raw, dataset, source, out_dir = argv
    fn = modes[tool]
    detections, auth = fn(Path(raw), dataset, source)
    out = Path(out_dir)
    _append(out / "detections.jsonl", detections)
    if auth:
        _append(out / "auth_events.jsonl", auth)
    if tool != "auth" or auth:
        print(f"{tool} {dataset}: {len(detections)} rules, {len(auth)} logon events")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
