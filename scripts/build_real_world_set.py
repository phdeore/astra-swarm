"""Build the real-world eval set from public detection output.

Phase 1 (propose):

    python -I scripts/build_real_world_set.py propose --workdir ~/astra-real-world

reads WORKDIR/out/detections.jsonl and auth_events.jsonl (from
scripts/real_world/collect.sh) plus OTRF's dataset metadata, applies
evals/label_mapping.json, and writes:

* evals/real_world_candidates.json: alerts with PROPOSED labels
  (``label_origin: "proposed"``) for a human to review;
* evals/real_world_auth_logs.json: the ITDR auth-log fixture for those alerts.

Phase 2 (review): edit the candidates file. For each row you accept, correct the
labels and set ``label_origin`` to ``"human"``; set ``"rejected"`` to drop it.

Phase 2 (finalize):

    python -I scripts/build_real_world_set.py finalize

writes evals/real_world_set.json with only the ``human`` rows.

Every input is untrusted downloaded data: it is parsed as JSON/YAML (safe_load) and
rendered as alert text, never executed. Timestamps are re-based per dataset onto one
timeline (``reference_time`` in the mapping) so the auth-log lookback windows line up;
intervals inside a dataset are preserved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

import yaml

from astra_swarm.guardrails import validate_alert_input

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "evals" / "label_mapping.json"
CANDIDATES_PATH = ROOT / "evals" / "real_world_candidates.json"
AUTH_FIXTURE_PATH = ROOT / "evals" / "real_world_auth_logs.json"
FINAL_PATH = ROOT / "evals" / "real_world_set.json"

OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
RULES_COMMIT = "58f8f145c65ed0bc0dcf888efde4ca9ca87ba846"
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
ESCALATING = {"high", "critical"}
AUTH_PER_USER = 50


# --- Small helpers -----------------------------------------------------------------------


def _ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stable(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _base_technique(tag: str) -> str:
    return tag.split(".")[0].upper()


def _private(ip: str) -> bool:
    try:
        return ip_address(ip).is_private
    except ValueError:
        return True  # "-", hostnames: local/lab


def _dataset_group(dataset: str) -> str:
    """net/apt29__day1__NASHUA/NASHUA.pcap → net/apt29 (for dataset_overrides)."""
    head = dataset.split("/", 2)
    return f"{head[0]}/{head[1].split('__')[0]}" if len(head) > 1 else dataset


# --- OTRF metadata -------------------------------------------------------------------------


def load_metadata(otrf: Path) -> dict[str, dict]:
    """Archive basename → {"title", "techniques", "tactics"} from OTRF _metadata/*.yaml."""
    out: dict[str, dict] = {}
    for meta in sorted((otrf / "datasets").glob("*/_metadata/*.yaml")):
        try:
            doc = yaml.safe_load(meta.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        techniques, tactics = [], []
        for m in doc.get("attack_mappings") or []:
            t = str(m.get("technique") or "").strip()
            sub = str(m.get("sub-technique") or "").strip()
            if t:
                techniques.append(f"{t}.{sub}" if sub else t)
            tactics.extend(str(x) for x in (m.get("tactics") or []))
        info = {"title": str(doc.get("title") or ""), "id": str(doc.get("id") or ""),
                "techniques": techniques, "tactics": tactics}
        for f in doc.get("files") or []:
            link = str(f.get("link") or "")
            if link:
                out[link.rsplit("/", 1)[-1].lower()] = info
    return out


def dataset_context(det: dict, metadata: dict, mapping: dict) -> dict:
    override = mapping["dataset_overrides"].get(_dataset_group(det["dataset"]))
    if override:
        return {"id": "", **override}
    archive = det["source"].rsplit("/", 1)[-1].lower()
    return metadata.get(archive, {"title": "", "id": "", "techniques": [], "tactics": []})


# --- Labelling -----------------------------------------------------------------------------


def _hayabusa_tactics(codes: list[str], mapping: dict) -> set[str]:
    table = mapping["hayabusa"]["tactic_codes"]
    return {table[c] for c in codes if c in table}


def label_hayabusa(det: dict, ctx: dict, mapping: dict) -> dict | None:
    m = mapping["hayabusa"]
    tags = [t for t in det.get("mitre_tags") or [] if re.fullmatch(r"T\d{4}(\.\d{3})?", str(t))]
    level = det.get("level", "")

    ident = m["identity_auth"]
    if (any(t.startswith(p) for t in tags for p in ident["technique_prefixes"])
            or det.get("event_id") in ident["event_ids"]
            or det.get("channel") in ident["channels"]):
        routing = "identity_auth"
    elif any(t.startswith(p) for t in tags for p in m["other"]["technique_prefixes"]):
        routing = "other"
    elif not tags and (det.get("channel") in m["other"]["untagged_channels"] or any(
            s.lower() in det.get("rule_title", "").lower() for s in m["other"]["untagged_title_substrings"])):
        routing = "other"  # operational/availability events
    else:
        routing = m["default_routing"]

    ds_bases = {_base_technique(t) for t in ctx["techniques"]}
    ds_tactics = _hayabusa_tactics(ctx["tactics"], mapping)
    det_tactics = set(det.get("mitre_tactics") or [])
    technique_hit = bool(ds_bases & {_base_technique(t) for t in tags})
    tactic_hit = bool(ds_tactics & det_tactics) and level in ("med", "high", "crit")

    if technique_hit or tactic_hit:
        verdict = "malicious"
        severity = m["severity_from_level"].get(level, "medium")
        why = (f"rule technique matches the simulated {', '.join(sorted(ds_bases))}" if technique_hit
               else f"rule tactic {', '.join(sorted(ds_tactics & det_tactics))} matches the simulation")
    elif level in m["benign_levels"]:
        verdict, severity = "benign", "low"
        why = ("rule has no ATT&CK tag, so it could not be matched to the simulation: check whether it is "
               "part of the attack" if not tags else
               "background activity in the lab capture; the rule is unrelated to the simulated technique")
    else:
        return None  # a medium+ rule unrelated to the simulation: too ambiguous to propose

    return {"routing": routing, "verdict": verdict, "severity": severity, "why": why,
            "tactics": det_tactics | (ds_tactics if verdict == "malicious" else set())}


def label_suricata(det: dict, ctx: dict, mapping: dict) -> dict | None:
    m = mapping["suricata"]
    lo, hi = m["bsd_sid_range"]
    if det.get("gid", 1) != 1 or not lo <= int(det["sid"]) <= hi:
        return None  # outside the BSD-licensed ET Open range
    sig, cat = det.get("signature", ""), det.get("category", "")

    if any(sig.startswith(p) for p in m["malware_signature_prefixes"]) or cat in m["malware_categories"]:
        routing = "malware"
    elif any(sig.startswith(p) for p in m["other_signature_prefixes"]) or any(
            s.lower() in sig.lower() for s in m["other_signature_substrings"]):
        routing = "other"
    else:
        routing = m["default_routing"]

    benign = cat in m["benign_categories"] or any(s.lower() in sig.lower() for s in m["benign_signature_substrings"])
    ds_tactics = _hayabusa_tactics(ctx["tactics"], mapping)
    if benign:
        return {"routing": routing, "verdict": "benign", "severity": "low", "tactics": set(),
                "why": f"'{cat}' traffic that also occurs outside the simulation"}
    severity = m["severity_from_priority"].get(str(det.get("severity")), "medium")
    return {"routing": routing, "verdict": "malicious", "severity": severity, "tactics": ds_tactics,
            "why": "signature fired on the capture of the simulated attack"}


def expected_workers(routing: str, label: dict, mapping: dict) -> list[str]:
    w = mapping["workers"]
    workers = list(w["always"])
    if routing in w["itdr_for_routing"]:
        workers.append("itdr_specialist")
    if label["verdict"] == "malicious" and label["tactics"] & set(w["soc_analyst_tactics"]):
        workers.append("soc_analyst")
    return workers


# --- Rendering -------------------------------------------------------------------------------


def load_channel_names(rules_config: Path | None) -> dict[str, str]:
    """Hayabusa abbreviation → full channel name (from its channel_abbreviations.txt)."""
    names = {"Sec": "Security", "Sys": "System", "App": "Application", "PwSh": "Microsoft-Windows-PowerShell/Operational"}
    if rules_config and (rules_config / "channel_abbreviations.txt").is_file():
        for line in (rules_config / "channel_abbreviations.txt").read_text(errors="replace").splitlines()[1:]:
            full, _, abbr = line.rpartition(",")
            if full and abbr:
                names.setdefault(abbr.strip(), full.strip())
    return names


def _shift(ts: str, offset: timedelta) -> str:
    dt = _ts(ts)
    return _iso(dt + offset) if dt else ts


def _fit(alert: dict, limit: int) -> str:
    """Serialise, shrinking the details block until the alert fits."""
    text = json.dumps(alert, ensure_ascii=False)
    details = alert.get("details")
    while len(text) > limit and isinstance(details, dict) and details:
        longest = max(details, key=lambda k: len(json.dumps(details[k], ensure_ascii=False)))
        v = details[longest]
        if isinstance(v, str) and len(v) > 80:
            details[longest] = v[: max(40, len(v) // 2)] + "…"
        else:
            details.pop(longest)
        text = json.dumps(alert, ensure_ascii=False)
    return text


def render_hayabusa(det: dict, offset: timedelta, channels: dict, mapping: dict) -> str:
    s = det["samples"][0]
    level = mapping["hayabusa"]["level_names"].get(det.get("level", ""), det.get("level", ""))
    alert = {
        "timestamp": _shift(s.get("ts", ""), offset),
        "source": "Hayabusa/Sigma",
        "rule": det.get("rule_title", ""),
        "level": level,
        "host": s.get("computer", ""),
        "channel": channels.get(det.get("channel", ""), det.get("channel", "")),
        "event_id": det.get("event_id"),
        "mitre": det.get("mitre_tags") or [],
        "details": dict(s.get("details") or {}),
        "occurrences": det.get("count", 1),
        # DRL 1.1: messages based on rule matches must retain the rule author.
        "rule_id": det.get("rule_id", ""),
        "rule_author": det.get("rule_author", ""),
    }
    return _fit(alert, mapping["selection"]["max_alert_chars"])


def render_suricata(det: dict, offset: timedelta, mapping: dict) -> str:
    s = det["samples"][0]
    ts = _shift(s.get("ts", ""), offset)
    if int(_stable(det["dataset"] + str(det["sid"]))[:2], 16) % 3 == 0:
        # Suricata fast.log line, as a sensor forwarding plain syslog would send it.
        dt = _ts(ts)
        stamp = dt.strftime("%m/%d/%Y-%H:%M:%S.%f") if dt else ts
        return (f"{stamp}  [**] [1:{det['sid']}:{det.get('rev', 1)}] {det.get('signature', '')} [**] "
                f"[Classification: {det.get('category', '')}] [Priority: {det.get('severity', '')}] "
                f"{{{s.get('proto', '')}}} {s.get('src_ip')}:{s.get('src_port')} -> {s.get('dest_ip')}:{s.get('dest_port')}"
                f" count={det.get('count', 1)}")
    alert = {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": s.get("src_ip"), "src_port": s.get("src_port"),
        "dest_ip": s.get("dest_ip"), "dest_port": s.get("dest_port"),
        "proto": s.get("proto"), "app_proto": s.get("app_proto"),
        "alert": {"signature_id": det["sid"], "rev": det.get("rev"), "signature": det.get("signature", ""),
                  "category": det.get("category", ""), "severity": det.get("severity")},
        "count": det.get("count", 1),
        "details": {k: s[k] for k in ("http", "tls", "dns", "smb") if k in s},
    }
    if not alert["details"]:
        del alert["details"]
    return _fit(alert, mapping["selection"]["max_alert_chars"])


# --- Proposal ----------------------------------------------------------------------------------


def dataset_offsets(detections: list[dict], auth: list[dict], reference: datetime) -> dict[str, timedelta]:
    last: dict[str, datetime] = {}
    for rec in detections:
        dt = _ts(rec.get("last_ts", ""))
        if dt and (rec["dataset"] not in last or dt > last[rec["dataset"]]):
            last[rec["dataset"]] = dt
    for rec in auth:
        dt = _ts(rec.get("ts", ""))
        if dt and (rec["dataset"] not in last or dt > last[rec["dataset"]]):
            last[rec["dataset"]] = dt
    # Whole seconds keep the shifted timestamps readable.
    return {ds: timedelta(seconds=round((reference - dt).total_seconds())) for ds, dt in last.items()}


def check_alert(alert: str, mapping: dict) -> str | None:
    """Why an alert can't be used, or None."""
    sel = mapping["selection"]
    if len(alert) > sel["max_alert_chars"]:
        return "too long"
    verdict = validate_alert_input(alert)
    if not verdict.passed:
        return f"guardrail: {verdict.reason}"
    return None


def propose(detections: list[dict], auth: list[dict], metadata: dict, mapping: dict,
            channels: dict) -> tuple[list[dict], list[dict], Counter]:
    reference = _ts(mapping["reference_time"])
    assert reference is not None
    offsets = dataset_offsets(detections, auth, reference)
    sel = mapping["selection"]
    dropped: Counter = Counter()

    pool: dict[tuple[str, str], list[dict]] = defaultdict(list)  # (class, verdict) → rows
    seen_rules: set[str] = set()
    # Strongest first so each rule is represented by its most relevant dataset.
    order = sorted(detections, key=lambda d: (-SEVERITY_RANK.get(
        mapping["hayabusa"]["severity_from_level"].get(d.get("level", ""), "low"), 0), _stable(d["dataset"] + str(d.get("rule_id") or d.get("sid")))))
    for det in order:
        if not det.get("samples"):
            continue
        ctx = dataset_context(det, metadata, mapping)
        if det["tool"] == "hayabusa":
            if not det.get("rule_author"):
                dropped["no rule author (DRL attribution)"] += 1
                continue
            if det.get("rule_status") == "deprecated" or det.get("level") in mapping["hayabusa"]["skip_levels"]:
                continue  # informational Hayabusa hits are event telemetry, not alerts
            label = label_hayabusa(det, ctx, mapping)
            rule_key = f"h:{det['rule_id']}"
        else:
            label = label_suricata(det, ctx, mapping)
            rule_key = f"s:{det['sid']}"
            if label is None:
                dropped["SID outside BSD range"] += 1
                continue
        if label is None:
            dropped["ambiguous (unrelated medium+ rule)"] += 1
            continue
        title_key = re.sub(r"[^a-z0-9]+", " ", (det.get("rule_title") or det.get("signature", "")).lower()).strip()
        if rule_key in seen_rules or title_key in seen_rules:
            continue  # Hayabusa ships the same rule for several log sources under new IDs
        offset = offsets.get(det["dataset"], timedelta(0))
        alert = (render_hayabusa(det, offset, channels, mapping) if det["tool"] == "hayabusa"
                 else render_suricata(det, offset, mapping))
        problem = check_alert(alert, mapping)
        if problem:
            dropped[problem] += 1
            continue
        seen_rules.update((rule_key, title_key))
        routing = label["routing"]
        title = det.get("rule_title") or det.get("signature", "")
        techniques = ", ".join(ctx["techniques"]) or "n/a"
        row = {
            "alert": alert,
            "expected_routing": routing,
            "expected_severity": label["severity"],
            "expected_escalation": label["severity"] in ESCALATING,
            "expected_workers_contains": expected_workers(routing, label, mapping),
            "label_notes": (f"PROPOSED ({label['verdict']}): {det['tool']} '{title}' on OTRF "
                            f"'{ctx['title'] or det['dataset']}' (ATT&CK {techniques}); {label['why']}."),
            "label_origin": "proposed",
            "proposed_verdict": label["verdict"],
            "source": {
                "dataset": det["dataset"],
                "archive": det["source"],
                "otrf_id": ctx.get("id", ""),
                "tool": det["tool"],
                "rule": title,
                "rule_id": det.get("rule_id") or str(det.get("sid")),
                "rule_author": det.get("rule_author", "") if det["tool"] == "hayabusa" else "Emerging Threats (ET Open)",
                "rule_licence": "DRL-1.1" if det["tool"] == "hayabusa" else "BSD (ET Open SID 2000000-2099999)",
                "data_licence": "MIT (OTRF Security-Datasets)",
                "occurrences": det.get("count", 1),
                "time_offset_seconds": int(offset.total_seconds()),
            },
        }
        pool[(routing, label["verdict"])].append(row)

    chosen: list[dict] = []
    per_dataset: Counter = Counter()
    # Scarcest class first, so a shared per-dataset slot goes to the class that needs it.
    for cls in sorted(sel["classes"], key=lambda c: (len(pool[(c, "malicious")]) + len(pool[(c, "benign")]), c)):
        want = sel.get("candidates_per_class_overrides", {}).get(cls, sel["candidates_per_class"])
        n_benign = round(want * sel["benign_share"])
        picks: list[dict] = []
        for verdict, quota in (("benign", n_benign), ("malicious", want - n_benign)):
            for row in pool[(cls, verdict)]:
                if len([p for p in picks if p["proposed_verdict"] == verdict]) >= quota:
                    break
                if per_dataset[row["source"]["dataset"]] >= sel["max_rows_per_dataset"]:
                    continue
                picks.append(row)
                per_dataset[row["source"]["dataset"]] += 1
        # Top up from the other verdict if one side ran short.
        for verdict in ("malicious", "benign"):
            for row in pool[(cls, verdict)]:
                if len(picks) >= want:
                    break
                if row in picks or per_dataset[row["source"]["dataset"]] >= sel["max_rows_per_dataset"]:
                    continue
                picks.append(row)
                per_dataset[row["source"]["dataset"]] += 1
        chosen.extend(picks)
    chosen.sort(key=lambda r: (sel["classes"].index(r["expected_routing"]), r["proposed_verdict"], r["source"]["rule"]))

    fixture = build_auth_fixture(chosen, auth, offsets)
    return chosen, fixture, dropped


def build_auth_fixture(rows: list[dict], auth: list[dict], offsets: dict[str, timedelta]) -> list[dict]:
    """Logons for users named in the chosen alerts, re-based like the alerts."""
    text = "\n".join(r["alert"] for r in rows).lower()
    by_user: dict[str, list[dict]] = defaultdict(list)
    for rec in auth:
        user = rec["user"]
        if len(user) < 3 or not re.search(rf"(?<![\w.]){re.escape(user.lower())}(?![\w])", text):
            continue
        offset = offsets.get(rec["dataset"], timedelta(0))
        reason = f"event {rec['event_id']}" + (f", logon type {rec['logon_type']}" if rec.get("logon_type") else "")
        if rec.get("status") and rec["result"] == "fail":
            reason += f", status {rec['status']}"
        by_user[user].append({
            "ts": _shift(rec["ts"], offset),
            "user": user,
            "src_ip": rec["src_ip"],
            "geo": "internal (lab network)" if _private(rec["src_ip"]) else "unknown",
            "result": rec["result"],
            "mfa_challenge": False,
            "device_id": rec.get("computer", ""),
            "reason": reason,
        })
    out: list[dict] = []
    for user in sorted(by_user):
        entries = sorted(by_user[user], key=lambda e: e["ts"])
        out.extend(entries[-AUTH_PER_USER:])
    return sorted(out, key=lambda e: (e["ts"], e["user"]))


# --- CLI -----------------------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _write(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def cmd_propose(args) -> int:
    w = Path(args.workdir).expanduser()
    mapping = json.loads(MAPPING_PATH.read_text())
    detections = _read_jsonl(w / "out" / "detections.jsonl")
    if not detections:
        print(f"no detections in {w / 'out'}: run scripts/real_world/collect.sh first", file=sys.stderr)
        return 3
    auth = _read_jsonl(w / "out" / "auth_events.jsonl")
    metadata = load_metadata(w / "src" / "otrf")
    channels = load_channel_names(w / "tools" / "hayabusa-rules" / "config")
    rows, fixture, dropped = propose(detections, auth, metadata, mapping, channels)

    if CANDIDATES_PATH.exists() and not args.force:
        reviewed = [r for r in json.loads(CANDIDATES_PATH.read_text()) if r.get("label_origin") != "proposed"]
        if reviewed:
            print(f"{CANDIDATES_PATH.name} has {len(reviewed)} reviewed rows; pass --force to overwrite", file=sys.stderr)
            return 3
    _write(CANDIDATES_PATH, rows)
    _write(AUTH_FIXTURE_PATH, fixture)

    by = Counter((r["expected_routing"], r["proposed_verdict"]) for r in rows)
    print(f"{len(rows)} candidates → {CANDIDATES_PATH.relative_to(ROOT)}")
    for cls in mapping["selection"]["classes"]:
        print(f"  {cls:14s} malicious={by[(cls, 'malicious')]:2d} benign={by[(cls, 'benign')]:2d}")
    print(f"{len(fixture)} auth-log entries for {len({e['user'] for e in fixture})} users → {AUTH_FIXTURE_PATH.relative_to(ROOT)}")
    for reason, n in dropped.most_common():
        print(f"  dropped {n:5d}: {reason}")
    return 0


REQUIRED = ("alert", "expected_routing", "expected_severity", "expected_escalation",
            "expected_workers_contains", "label_notes")


def cmd_finalize(args) -> int:
    mapping = json.loads(MAPPING_PATH.read_text())
    rows = json.loads(CANDIDATES_PATH.read_text())
    human = [r for r in rows if r.get("label_origin") == "human"]
    problems = []
    for i, r in enumerate(human):
        missing = [k for k in REQUIRED if k not in r]
        if missing:
            problems.append(f"row {i}: missing {missing}")
        elif r["expected_escalation"] != (r["expected_severity"] in ESCALATING):
            problems.append(f"row {i}: escalation must be true exactly for high/critical severity")
        elif (why := check_alert(r["alert"], mapping)):
            problems.append(f"row {i}: {why}")
        elif r["label_notes"].startswith("PROPOSED"):
            problems.append(f"row {i}: label_notes still says PROPOSED; write the reviewer's reasoning")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    _write(FINAL_PATH, human)
    by = Counter(r["expected_routing"] for r in human)
    print(f"{len(human)} human-reviewed rows → {FINAL_PATH.relative_to(ROOT)}  {dict(sorted(by.items()))}")
    short = [c for c in mapping["selection"]["classes"] if by[c] < mapping["selection"]["final_per_class"]]
    if short:
        print(f"note: below {mapping['selection']['final_per_class']} rows for {short}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("propose", help="build candidates from collect.sh output")
    pp.add_argument("--workdir", default="~/astra-real-world")
    pp.add_argument("--force", action="store_true", help="overwrite reviewed candidates")
    sub.add_parser("finalize", help="write the human-reviewed rows to the eval set")
    args = p.parse_args(argv)
    return cmd_propose(args) if args.cmd == "propose" else cmd_finalize(args)


if __name__ == "__main__":
    sys.exit(main())
