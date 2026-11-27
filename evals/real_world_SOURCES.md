# Real-world eval set: sources, licences and how it was built

`evals/real_world_set.json` contains alerts produced by running open detection rules over
public attack-simulation logs. Only the derived alerts and labels are committed. The raw
logs and PCAPs are never committed; rebuild them with the commands below.

## Inputs (pinned)

| Input | Version | Licence | Used for |
|---|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` (2023-09-20) | MIT | Windows host logs (`datasets/atomic/windows/*/host`, plus the Windows host logs of `compound/Log4Shell`, `compound/LSASS_campaign_*` and `compound/apt29`), network captures (`atomic/windows/*/network`, `compound/Log4Shell`, `compound/LSASS_campaign_*`, `compound/apt29/day*/pcaps`) and ATT&CK mappings (`_metadata/*.yaml`) |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | v4.4.0, `hayabusa-4.4.0-mac-aarch64.zip` sha256 `f14ba1242b7fb67fefe02bfc7a3592486458ac853e2925f5b8712725e6253604` | AGPL-3.0 (tool only, run locally; nothing from it is committed) | Sigma/Hayabusa detections over the host logs |
| [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) | commit `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846` (2026-11-10) | [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) | Rules (Sigma and Hayabusa-native) |
| [Suricata](https://suricata.io) | 8.0.8 (Homebrew) | GPL-2.0 (tool only, run locally) | IDS alerts over the captures |
| [ET Open](https://rules.emergingthreats.net) | fetched with `suricata-update` on 2026-11-27 | BSD for SIDs 2000000–2099999 ([ET FAQ](https://community.emergingthreats.net/t/frequently-asked-questions/56), [licensing](https://community.emergingthreats.net/t/licensing-of-third-party-rules/2396)) | Only alerts from that SID range are kept |

**Excluded on licence grounds:** phishing corpora such as phishing_pot (CC BY-NC 4.0,
non-commercial) and SpamAssassin (no licence), so v1 has **no phishing rows**;
EVTX-ATTACK-SAMPLES (GPL-3.0); Suricata's own decoder/app-layer rules (SID 22xxxxx) and
ET rules outside the BSD range; malware-traffic-analysis.net (terms not found).

**Attribution.** DRL 1.1 requires that messages based on rule matches retain the rule
author, so every Hayabusa alert carries `rule_author` and `rule_id`, and each row's
`source` names the rule, its licence and the OTRF archive and dataset ID it came from.
OTRF data © Open Threat Research Forge, MIT licence.

## Rebuild

Everything runs in a scratch folder outside the repo, never in CI. The inputs are
downloaded attack data.

```sh
W=~/astra-real-world && mkdir -p $W/{src,tools,out} && cd $W
git clone --filter=blob:none https://github.com/OTRF/Security-Datasets src/otrf
git -C src/otrf checkout d9d40ef123d2c87d5d3df28c96bcab4f0faccc87
curl -LO https://github.com/Yamato-Security/hayabusa/releases/download/v4.4.0/hayabusa-4.4.0-mac-aarch64.zip
echo "f14ba1242b7fb67fefe02bfc7a3592486458ac853e2925f5b8712725e6253604  hayabusa-4.4.0-mac-aarch64.zip" | shasum -a 256 -c
unzip -q hayabusa-4.4.0-mac-aarch64.zip -d tools/hayabusa && chmod +x tools/hayabusa/hayabusa-4.4.0-mac-aarch64
git clone --filter=blob:none https://github.com/Yamato-Security/hayabusa-rules tools/hayabusa-rules
git -C tools/hayabusa-rules checkout 58f8f145c65ed0bc0dcf888efde4ca9ca87ba846
brew install suricata && suricata-update -D tools/suricata

cd <repo>
scripts/real_world/collect.sh $W                                    # ~20 min, resumable
python -I scripts/build_real_world_set.py propose --workdir $W      # candidates + auth fixture
# review evals/real_world_candidates.json (below), then:
python -I scripts/build_real_world_set.py finalize                  # evals/real_world_set.json
```

`collect.sh` checks every pin, extracts each archive into its own empty folder, runs the
tool and deletes the extraction. `condense.py` (run with `python -I`) keeps one record per
dataset and rule, with up to three samples. ET Open is not pinned by version (ET
publishes daily), so a rebuild may yield slightly different network alerts.

## How labels are proposed, then reviewed

`evals/label_mapping.json` holds every rule. In short:

- **Routing** follows the router's class definitions. Kerberos/NTLM/logon/account events
  and identity ATT&CK techniques → `identity_auth`. Data collection/exfiltration,
  web-application exploits (Log4Shell) and untagged operational events → `other`. ET
  MALWARE/TROJAN/CNC signatures → `malware`. Other IDS alerts → `network`. Other host
  detections → `malware`.
- **Verdict:** a detection whose ATT&CK technique (or tactic, for medium+ rules) matches
  the technique the OTRF dataset simulates is `malicious`. A low or informational rule
  unrelated to the simulation is `benign` background. An unrelated medium+ rule is
  ambiguous and is not proposed.
- **Severity** comes from the rule level or IDS priority (benign → `low`). **Escalation**
  is `true` exactly for high/critical, matching the graph's deterministic rule.
- **Workers:** always `enrichment`; `itdr_specialist` for `identity_auth`; `soc_analyst`
  for malicious rows whose tactics include lateral movement, C2, exfiltration or impact
  (the supervisor's rule).
- **Selection:** 18 candidates per class (24 for `malware`, which has by far the largest
  pool), about 40% benign, at most one row per rule title and two per dataset, scarcest
  class first. Hayabusa `informational` hits are event telemetry, not alerts, and are skipped. Alerts over 2000 characters, or ones that trip the input guardrails,
  are dropped.

**Review.** In `evals/real_world_candidates.json`, for each row: read the alert, fix any
label, replace `label_notes` with your own reasoning, and set `label_origin` to `"human"`
(keep) or `"rejected"` (drop). `finalize` keeps only `human` rows and rejects rows whose
escalation disagrees with severity or whose notes still start with `PROPOSED`.

## Caveats

- **Lab data, not production.** Hosts, users and IPs are OTRF lab assets (e.g.
  `pandalab.com`, `theshire.local`, private addresses). Background noise is far lower
  than in a real SOC, and "benign" rows are lab background activity.
- **Timestamps are re-based.** Each dataset is shifted by a whole-second offset so its
  last event lands on `reference_time` (2026-09-28T12:00:00Z), keeping ITDR's 336-hour
  lookback meaningful across datasets recorded in 2019–2023. The offset is stored in
  `source.time_offset_seconds`; intervals within a dataset are unchanged.
- **Auth-log fixture** (`evals/real_world_auth_logs.json`): real 4624/4625/4648/4768/4769/
  4771/4776 events from the same datasets, only for users named in the chosen alerts
  (newest 50 per user, machine and service accounts dropped). Geo is unknown for lab
  data (`internal (lab network)`), and MFA is not recorded, so MFA-fatigue and
  impossible-travel patterns cannot be shown.
- **The class mix is limited by the data:** OTRF has no email telemetry and few
  data-loss events. Only 12 distinct rules qualify as `other` (mostly Log4Shell IDS
  alerts), so `other` has about 9 candidates against a target of 15, and network has only
  3 benign candidates. Results for those cells have wide intervals.
- **APT29** has no OTRF metadata file; its techniques come from `dataset_overrides` in
  the mapping, taken from the published emulation plan.
