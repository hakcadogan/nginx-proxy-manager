#!/usr/bin/env bash
# REQ-QA-008 — lightweight load smoke against panel health
set -euo pipefail
BASE="${BASE_URL:-http://localhost:28080}"
N="${N:-50}"
fail=0
for i in $(seq 1 "$N"); do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/v1/health" || echo 000)
  if [ "$code" != "200" ]; then
    fail=$((fail+1))
  fi
done
echo "load smoke: $N requests, failures=$fail"
test "$fail" -eq 0
echo "PASS load smoke"
