#!/usr/bin/env bash
# Phase 0 of the real-world eval set: run the detection tools over public lab data.
#
#   scripts/real_world/collect.sh [WORKDIR]      (default: ~/astra-real-world)
#
# Expects the pinned downloads described in evals/real_world_SOURCES.md under WORKDIR:
#   src/otrf                    OTRF Security-Datasets (MIT) at $OTRF_COMMIT
#   tools/hayabusa/             Hayabusa $HAYABUSA_VERSION binary + its config/
#   tools/hayabusa-rules        hayabusa-rules (DRL 1.1) at $RULES_COMMIT
#   tools/suricata/rules        ET Open via `suricata-update -D tools/suricata`
#
# Writes WORKDIR/out/detections.jsonl and WORKDIR/out/auth_events.jsonl, one record per
# (dataset, rule), for scripts/build_real_world_set.py. Raw logs and PCAPs stay in
# WORKDIR and are never copied into the repo. Each archive is extracted into its own
# empty directory, scanned and deleted. Re-running skips datasets already in out/done.txt.
#
# Never run in CI: the inputs are downloaded attack data.
set -euo pipefail

OTRF_COMMIT=d9d40ef123d2c87d5d3df28c96bcab4f0faccc87
RULES_COMMIT=58f8f145c65ed0bc0dcf888efde4ca9ca87ba846
HAYABUSA_VERSION=4.4.0
HAYABUSA_ZIP_SHA256=f14ba1242b7fb67fefe02bfc7a3592486458ac853e2925f5b8712725e6253604
SURICATA_VERSION=8.0.8
APT29_ZIP_PASSWORD=infected  # published in OTRF's README next to the archives

W=$(cd "${1:-$HOME/astra-real-world}" && pwd)
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONDENSE="$HERE/condense.py"
O="$W/src/otrf/datasets"
H="$W/tools/hayabusa/hayabusa-$HAYABUSA_VERSION-mac-aarch64"
R="$W/tools/hayabusa-rules"
SURI_RULES="$W/tools/suricata/rules/suricata.rules"
SURI_CONF=${SURICATA_CONF:-$(brew --prefix 2>/dev/null || echo /opt/homebrew)/etc/suricata/suricata.yaml}
OUT="$W/out"
X="$W/extract"

die() { echo "error: $*" >&2; exit 3; }

# --- Pins ------------------------------------------------------------------------------
[ "$(git -C "$W/src/otrf" rev-parse HEAD)" = "$OTRF_COMMIT" ] || die "src/otrf is not at $OTRF_COMMIT"
[ "$(git -C "$R" rev-parse HEAD)" = "$RULES_COMMIT" ] || die "hayabusa-rules is not at $RULES_COMMIT"
if [ -f "$W/hayabusa-$HAYABUSA_VERSION-mac-aarch64.zip" ]; then
  echo "$HAYABUSA_ZIP_SHA256  $W/hayabusa-$HAYABUSA_VERSION-mac-aarch64.zip" | shasum -a 256 -c --quiet \
    || die "Hayabusa zip checksum mismatch"
fi
[ -x "$H" ] || die "Hayabusa binary missing or not executable: $H"
suricata -V | grep -q "version $SURICATA_VERSION" || die "need Suricata $SURICATA_VERSION"
[ -f "$SURI_RULES" ] || die "ET Open rules missing: run suricata-update -D $W/tools/suricata"
[ -f "$SURI_CONF" ] || die "suricata.yaml not found (set SURICATA_CONF)"

mkdir -p "$OUT" "$X"
touch "$OUT/done.txt"
# Python reads untrusted output: isolated mode, run from a directory we control.
py() { (cd "$HERE" && python3 -I "$CONDENSE" "$@"); }
fresh() { rm -rf "$1" && mkdir -p "$1"; }

# --- Host logs → Hayabusa --------------------------------------------------------------
shopt -s nullglob
# Atomic Windows host logs, plus the Windows host logs of compound campaigns (Zeek and
# Linux auditd archives are skipped: Hayabusa reads Windows events only).
for z in "$O"/atomic/windows/*/host/*.zip \
         "$O"/compound/Log4Shell/securityauditing_*.zip "$O"/compound/Log4Shell/sysmon_*.zip \
         "$O"/compound/LSASS_campaign_0*/metasploit_*_lsass_memory_dump.zip \
         "$O"/compound/apt29/day*/apt29_evals_day*_manual.zip; do
  ds="host/$(basename "$z" .zip)"
  grep -qxF "$ds" "$OUT/done.txt" && continue
  d="$X/$ds"; fresh "$d"
  unzip -qo -P "$APT29_ZIP_PASSWORD" "$z" -d "$d"
  tl="$X/hayabusa-timeline.jsonl"; rm -f "$tl"
  (cd "$X" && "$H" dfir-timeline -J -d "$d" -r "$R" -c "$R/config" \
      -w -q -Q -K -N -U -O -C -t jsonl -p super-verbose -o "$tl" >/dev/null)
  if [ -f "$tl" ]; then py hayabusa "$tl" "$ds" "${z#"$W/src/otrf/"}" "$OUT"; fi
  py auth "$d" "$ds" "${z#"$W/src/otrf/"}" "$OUT"
  rm -rf "$d" "$tl"
  echo "$ds" >> "$OUT/done.txt"
done

# --- Network captures → Suricata (ET Open) ---------------------------------------------
{
  find "$O" -path '*/network/*' -name '*.zip'
  find "$O/compound" -iname '*pcap*.zip'
  find "$O/compound/apt29" -path '*/pcaps/*' -name '*.zip'
} | sort -u | while read -r z; do
  ds="net/$(echo "${z#"$O/"}" | sed -E 's#/(network|pcaps)/#/#; s#^(atomic/windows|compound)/##; s#\.zip$##; s#/#__#g')"
  grep -qxF "$ds" "$OUT/done.txt" && continue
  d="$X/$ds"; fresh "$d"
  unzip -qo -P "$APT29_ZIP_PASSWORD" "$z" -d "$d"
  find "$d" -type f \( -name '*.cap' -o -name '*.pcap' -o -name '*.pcapng' \) | sort | while read -r p; do
    log="$X/suricata-log"; fresh "$log"
    suricata -c "$SURI_CONF" -S "$SURI_RULES" -k none -r "$p" -l "$log" \
      --set outputs.1.eve-log.types='[alert]' >/dev/null 2>&1 || echo "warn: suricata failed on $p" >&2
    if [ -f "$log/eve.json" ]; then py suricata "$log/eve.json" "$ds/$(basename "$p")" "${z#"$W/src/otrf/"}" "$OUT"; fi
  done
  rm -rf "$d" "$X/suricata-log"
  echo "$ds" >> "$OUT/done.txt"
done

echo "done: $(wc -l < "$OUT/detections.jsonl") detection groups, $(wc -l < "$OUT/auth_events.jsonl" 2>/dev/null || echo 0) logon events in $OUT"
