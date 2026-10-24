#!/usr/bin/env bash
# REQ-QA-009 — every REQ in REQUIREMENTS.md must appear in a PHASE plan.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALL=$(mktemp)
PHASES=$(mktemp)
grep -oE 'REQ-[A-Z]+-[0-9]+' "$ROOT/docs/REQUIREMENTS.md" | sort -u >"$ALL"
grep -oE 'REQ-[A-Z]+-[0-9]+' "$ROOT"/plans/PHASE_*.md | sed 's/.*://' | sort -u >"$PHASES"
MISSING=$(comm -23 "$ALL" "$PHASES" || true)
EXTRA=$(comm -13 "$ALL" "$PHASES" || true)
echo "REQ catalog: $(wc -l <"$ALL")"
echo "In phases:   $(wc -l <"$PHASES")"
if [[ -n "$MISSING" ]]; then
  echo "MISSING from phases:"
  echo "$MISSING"
  exit 1
fi
if [[ -n "$EXTRA" ]]; then
  echo "NOTE extras in phases (cross-refs ok):"
  echo "$EXTRA"
fi
echo "Traceability OK"
rm -f "$ALL" "$PHASES"
