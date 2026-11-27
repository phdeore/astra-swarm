"""Builder rules for the real-world set, and invariants of the committed set."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from astra_swarm.guardrails import validate_alert_input

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("build_real_world_set", ROOT / "scripts" / "build_real_world_set.py")
b = importlib.util.module_from_spec(_spec)
sys.modules["build_real_world_set"] = b
_spec.loader.exec_module(b)

MAPPING = json.loads((ROOT / "evals" / "label_mapping.json").read_text())
CTX = {"title": "Dumping NTDS.dit", "id": "SDWIN-1", "techniques": ["T1003.003"], "tactics": ["TA0006"]}
NO_CTX = {"title": "", "id": "", "techniques": [], "tactics": []}


def _hay(**kw) -> dict:
    det = {
        "tool": "hayabusa", "dataset": "host/ntds", "source": "datasets/atomic/windows/credential_access/host/ntds.zip",
        "rule_id": "r-1", "rule_title": "Suspicious NTDS", "rule_author": "Florian Roth", "rule_status": "test",
        "level": "high", "mitre_tactics": ["CredAccess"], "mitre_tags": ["T1003.003"], "channel": "Sec",
        "event_id": 4688, "count": 2, "first_ts": "2023-07-19T09:00:00Z", "last_ts": "2023-07-19T09:03:00Z",
        "samples": [{"ts": "2023-07-19T09:03:00Z", "computer": "DC01.lab", "details": {"Cmdline": "ntdsutil ifm", "User": "Administrator"}}],
    }
    det.update(kw)
    return det


def _sur(**kw) -> dict:
    det = {
        "tool": "suricata", "dataset": "net/lateral__psremoting/a.cap", "source": "datasets/atomic/windows/lateral_movement/network/x.zip",
        "sid": 2026849, "gid": 1, "rev": 3, "signature": "ET INFO WinRM wsman Access - Possible Lateral Movement",
        "category": "Potentially Bad Traffic", "severity": 2, "count": 23,
        "first_ts": "2020-09-20T17:08:00Z", "last_ts": "2020-09-20T17:09:00Z",
        "samples": [{"ts": "2020-09-20T17:08:27.1+00:00", "src_ip": "172.18.39.6", "src_port": 49721,
                     "dest_ip": "172.18.39.5", "dest_port": 5985, "proto": "TCP", "app_proto": "http"}],
    }
    det.update(kw)
    return det


# --- Labelling rules ---------------------------------------------------------------------


def test_hayabusa_attack_rule_is_malicious_with_level_severity():
    label = b.label_hayabusa(_hay(), CTX, MAPPING)
    assert (label["routing"], label["verdict"], label["severity"]) == ("malware", "malicious", "high")


def test_hayabusa_identity_by_technique_and_event_id():
    assert b.label_hayabusa(_hay(mitre_tags=["T1558.003"]), CTX, MAPPING)["routing"] == "identity_auth"
    assert b.label_hayabusa(_hay(mitre_tags=[], event_id=4625, level="low"), NO_CTX, MAPPING)["routing"] == "identity_auth"


def test_hayabusa_unrelated_low_rule_is_benign_and_untagged_is_other():
    label = b.label_hayabusa(_hay(mitre_tags=[], mitre_tactics=[], level="low", event_id=7034, channel="Sys",
                                  rule_title="Service Terminated With Error"), CTX, MAPPING)
    assert (label["routing"], label["verdict"], label["severity"]) == ("other", "benign", "low")
    assert "no ATT&CK tag" in label["why"]
    sysmon = b.label_hayabusa(_hay(mitre_tags=[], mitre_tactics=[], level="low", event_id=10, channel="Sysmon"), CTX, MAPPING)
    assert sysmon["routing"] == "malware"


def test_hayabusa_unrelated_high_rule_is_not_proposed():
    assert b.label_hayabusa(_hay(mitre_tags=["T1059.001"], mitre_tactics=["Exec"]), CTX, MAPPING) is None


def test_suricata_only_bsd_sids():
    assert b.label_suricata(_sur(sid=2200073, signature="SURICATA IPv4 invalid checksum"), NO_CTX, MAPPING) is None
    assert b.label_suricata(_sur(sid=2800001), NO_CTX, MAPPING) is None
    assert b.label_suricata(_sur(), NO_CTX, MAPPING)["routing"] == "network"


def test_suricata_classes():
    assert b.label_suricata(_sur(signature="ET MALWARE Cobalt Strike Beacon"), NO_CTX, MAPPING)["routing"] == "malware"
    assert b.label_suricata(_sur(signature="ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)"), NO_CTX, MAPPING)["routing"] == "other"
    benign = b.label_suricata(_sur(category="Not Suspicious Traffic"), NO_CTX, MAPPING)
    assert (benign["verdict"], benign["severity"]) == ("benign", "low")


def test_workers_follow_supervisor_rules():
    lat = {"verdict": "malicious", "tactics": {"LatMov"}}
    assert b.expected_workers("network", lat, MAPPING) == ["enrichment", "soc_analyst"]
    assert b.expected_workers("identity_auth", {"verdict": "benign", "tactics": {"LatMov"}}, MAPPING) == ["enrichment", "itdr_specialist"]


# --- Rendering -----------------------------------------------------------------------------


def test_hayabusa_alert_keeps_author_and_key_fields_up_front():
    alert = b.render_hayabusa(_hay(), timedelta(0), {"Sec": "Security"}, MAPPING)
    data = json.loads(alert)
    assert data["rule_author"] == "Florian Roth" and data["channel"] == "Security"
    head = alert[: MAPPING["selection"]["key_fields_within_chars"]]
    assert all(k in head for k in ("Suspicious NTDS", "DC01.lab", "4688", "ntdsutil"))


def test_long_details_are_trimmed_to_fit():
    det = _hay(samples=[{"ts": "2023-07-19T09:03:00Z", "computer": "h", "details": {f"k{i}": "x" * 290 for i in range(20)}}])
    alert = b.render_hayabusa(det, timedelta(0), {}, MAPPING)
    assert len(alert) <= MAPPING["selection"]["max_alert_chars"]
    assert json.loads(alert)["rule_author"] == "Florian Roth"


def test_timestamps_rebase_to_reference_per_dataset():
    ref = b._ts(MAPPING["reference_time"])
    offsets = b.dataset_offsets([_hay(), _sur()], [], ref)
    assert b._ts("2023-07-19T09:03:00Z") + offsets["host/ntds"] == ref
    assert b._ts("2020-09-20T17:09:00Z") + offsets["net/lateral__psremoting/a.cap"] == ref


# --- Proposal and finalize --------------------------------------------------------------------


def test_propose_dedups_rules_caps_datasets_and_builds_auth_fixture():
    dets = [
        _hay(),
        _hay(dataset="host/other"),  # same rule elsewhere → deduplicated
        _hay(rule_id="r-2", rule_title="Proc Access", level="low", mitre_tags=[], mitre_tactics=[], event_id=10),
        _hay(rule_id="r-3", rule_title="Another", level="med"),  # third row from host/ntds → capped
        _hay(rule_id="r-4", rule_author=""),  # no author → dropped (DRL attribution)
        _sur(),
        _sur(sid=2200073),
    ]
    auth = [{"dataset": "host/ntds", "ts": "2023-07-19T09:01:00Z", "user": "Administrator", "src_ip": "-",
             "result": "success", "event_id": 4624, "logon_type": "3", "computer": "DC01.lab", "status": ""},
            {"dataset": "host/ntds", "ts": "2023-07-19T09:01:00Z", "user": "nobody_here", "src_ip": "-",
             "result": "success", "event_id": 4624, "logon_type": "3", "computer": "DC01.lab", "status": ""}]
    rows, fixture, dropped = b.propose(dets, auth, {}, MAPPING, {"Sec": "Security"})
    rules = [r["source"]["rule_id"] for r in rows]
    assert len(rules) == len(set(rules))
    assert sum(r["source"]["dataset"] == "host/ntds" for r in rows) <= MAPPING["selection"]["max_rows_per_dataset"]
    assert "r-4" not in rules and dropped["no rule author (DRL attribution)"] == 1
    assert dropped["SID outside BSD range"] == 1
    assert all(r["label_origin"] == "proposed" for r in rows)
    assert {e["user"] for e in fixture} == {"Administrator"}
    assert fixture[0]["ts"].startswith("2026-09-28")


def test_finalize_keeps_only_reviewed_consistent_rows(tmp_path, monkeypatch):
    good = {"alert": "x", "expected_routing": "network", "expected_severity": "high", "expected_escalation": True,
            "expected_workers_contains": ["enrichment"], "label_notes": "Reviewed: WinRM from a lab host.",
            "label_origin": "human"}
    monkeypatch.setattr(b, "CANDIDATES_PATH", tmp_path / "c.json")
    monkeypatch.setattr(b, "FINAL_PATH", tmp_path / "f.json")
    monkeypatch.setattr(b, "ROOT", tmp_path)
    (tmp_path / "c.json").write_text(json.dumps([good, {**good, "label_origin": "proposed"}, {**good, "label_origin": "rejected"}]))
    assert b.main(["finalize"]) == 0
    assert json.loads((tmp_path / "f.json").read_text()) == [good]

    (tmp_path / "c.json").write_text(json.dumps([{**good, "expected_escalation": False}]))
    assert b.main(["finalize"]) == 1
    (tmp_path / "c.json").write_text(json.dumps([{**good, "label_notes": "PROPOSED (malicious): ..."}]))
    assert b.main(["finalize"]) == 1


# --- Committed set ----------------------------------------------------------------------------

FINAL = ROOT / "evals" / "real_world_set.json"


@pytest.mark.skipif(not FINAL.exists(), reason="real-world set not built yet")
def test_committed_real_world_set_invariants():
    rows = json.loads(FINAL.read_text())
    classes = set(MAPPING["selection"]["classes"])
    lo, hi = MAPPING["suricata"]["bsd_sid_range"]
    assert len(rows) >= 50
    for r in rows:
        assert r["label_origin"] == "human"
        assert r["expected_routing"] in classes  # no phishing rows in v1 (licensing)
        assert r["expected_escalation"] == (r["expected_severity"] in b.ESCALATING)
        assert "enrichment" in r["expected_workers_contains"]
        assert len(r["alert"]) <= MAPPING["selection"]["max_alert_chars"]
        assert validate_alert_input(r["alert"]).passed
        src = r["source"]
        if src["tool"] == "hayabusa":
            assert src["rule_author"] and src["rule_author"] in r["alert"]  # DRL 1.1
        else:
            assert lo <= int(src["rule_id"]) <= hi
            assert re.search(rf"\b{src['rule_id']}\b", r["alert"])
