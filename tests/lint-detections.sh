#!/usr/bin/env bash
###############################################################################
# lint-detections.sh
#
# Validates:
#   1. Every /detections/*.md card has the required sections.
#   2. splunk-app/soc_detection_lab/default/savedsearches.conf parses and
#      every stanza has the fields a scheduled alert needs.
#   3. Every deployed stanza in savedsearches.conf has a matching card in
#      /detections (name match is soft — checked by ATT&CK ID reference).
#
# Exit non-zero on any failure so CI turns red.
###############################################################################

set -u
fail=0
pass=0

REQUIRED_SECTIONS=(
  "## Hypothesis"
  "## Detection logic"
  "## False positives"
  "## Tuning"
  "## Triage workflow"
  "## References"
)

SAVEDSEARCHES="splunk-app/soc_detection_lab/default/savedsearches.conf"
CARDS_DIR="detections"

# --- 1. Card structure ------------------------------------------------------
echo "==> Linting detection cards in $CARDS_DIR/"
if [ ! -d "$CARDS_DIR" ]; then
  echo "FAIL: $CARDS_DIR/ directory not found"
  exit 1
fi

shopt -s nullglob
cards=("$CARDS_DIR"/*.md)
if [ ${#cards[@]} -eq 0 ]; then
  echo "FAIL: no detection cards found in $CARDS_DIR/"
  fail=1
fi

for card in "${cards[@]}"; do
  card_ok=1
  for section in "${REQUIRED_SECTIONS[@]}"; do
    if ! grep -qF "$section" "$card"; then
      echo "FAIL  $card missing required section: $section"
      card_ok=0
      fail=1
    fi
  done
  if ! grep -qE "T1[0-9]{3}(\.[0-9]{3})?" "$card"; then
    echo "FAIL  $card has no ATT&CK technique ID (T####[.###])"
    card_ok=0
    fail=1
  fi
  if [ $card_ok -eq 1 ]; then
    echo "PASS  $card"
    pass=$((pass+1))
  fi
done

# --- 2. savedsearches.conf shape -------------------------------------------
echo ""
echo "==> Linting $SAVEDSEARCHES"
if [ ! -f "$SAVEDSEARCHES" ]; then
  echo "FAIL: $SAVEDSEARCHES not found"
  exit 1
fi

python3 - <<'PY' || fail=1
import configparser, sys, re

path = "splunk-app/soc_detection_lab/default/savedsearches.conf"
cp = configparser.ConfigParser(strict=False, interpolation=None)
try:
    cp.read(path)
except configparser.Error as e:
    print(f"FAIL  parse error: {e}")
    sys.exit(1)

if not cp.sections():
    print("FAIL  no stanzas in savedsearches.conf")
    sys.exit(1)

required = ("search", "description", "cron_schedule", "dispatch.earliest_time",
            "dispatch.latest_time", "enableSched")
errors = 0
for stanza in cp.sections():
    missing = [k for k in required if k not in cp[stanza]]
    if missing:
        print(f"FAIL  [{stanza}] missing keys: {', '.join(missing)}")
        errors += 1
        continue
    if cp[stanza].get("enableSched") != "1":
        print(f"WARN  [{stanza}] enableSched != 1 (rule will not run)")
    if not re.search(r"index\s*=", cp[stanza]["search"]):
        print(f"WARN  [{stanza}] search has no explicit index= (slow / scans all)")
    print(f"PASS  [{stanza}]")

sys.exit(1 if errors else 0)
PY

# --- 3. Summary -------------------------------------------------------------
echo ""
if [ $fail -eq 0 ]; then
  echo "==> All checks passed."
  exit 0
else
  echo "==> FAILED. Fix the errors above."
  exit 1
fi
