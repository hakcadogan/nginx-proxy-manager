#!/usr/bin/env bash
# P04 WAF gate (REQ-WAF-001..012, REQ-RATE-004, REQ-API-007).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:28080}"
EDGE="${EDGE_URL:-http://localhost:8088}"
ADMIN_PASS="${ADMIN_PASS:-super-secret-12}"
CK="$(mktemp)"
trap 'rm -f "$CK" /tmp/waf-*.json' EXIT

echo "== unit: WAF overlay + mask =="
(cd "$ROOT/apps/api" && go test ./internal/nginxcfg/ ./internal/wafmask/ -count=1 -run 'TestWAF|TestRenderModSec|TestHostEngine|TestMask')

echo "== ModSec module loaded (REQ-WAF-001) =="
docker exec nsp-nginx-1 nginx -V 2>&1 | grep -qi modsecurity \
  || docker exec nsp-nginx-1 ls /etc/nginx/modules/ngx_http_modsecurity_module.so
docker exec nsp-nginx-1 test -f /opt/owasp-crs/crs-setup.conf \
  || docker exec nsp-nginx-1 test -f /opt/owasp-crs/crs-setup.conf.example
docker exec nsp-nginx-1 cat /etc/nginx/modsec/crs-version.txt | tee /tmp/waf-crs.txt
grep -qi 'CRS\|MODSECURITY\|4\.' /tmp/waf-crs.txt

curl -fsS "$BASE/api/v1/health" >/dev/null
LOGIN=$(curl -sS -c "$CK" -b "$CK" -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@example.com\",\"password\":\"$ADMIN_PASS\"}")
echo "$LOGIN" | grep -q csrf_token
CSRF=$(grep nsp_csrf "$CK" | awk '{print $7}')

api() {
  local method=$1 path=$2; shift 2
  curl -sS -c "$CK" -b "$CK" -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" "$@"
}

echo "== WAF policies API (REQ-API-007) =="
POLS=$(api GET /api/v1/waf/policies)
echo "$POLS" | grep -q '"scope":"global"'
POLICY_ID=$(echo "$POLS" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(next(p["id"] for p in d["items"] if p["scope"]=="global"))')
[[ -n "$POLICY_ID" ]]

echo "== ensure host + DetectionOnly apply =="
DOMAIN="waf-gate-$(date +%s).example.com"
HOST=$(api POST /api/v1/hosts -d "{
  \"primary_domain\":\"$DOMAIN\",
  \"upstream_scheme\":\"http\",
  \"upstream_host\":\"example.com\",
  \"upstream_port\":80,
  \"path_prefix\":\"/\",
  \"enabled\":true,
  \"waf_enabled\":true,
  \"aliases\":[],
  \"custom_headers\":[],
  \"locations\":[],
  \"websocket_support\":false,
  \"access_log_enabled\":true
}")
HOST_ID=$(echo "$HOST" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)

# Isolate: disable other hosts
curl -sS -b "$CK" "$BASE/api/v1/hosts" | python3 -c '
import json,sys
d=json.load(sys.stdin); keep=sys.argv[1]
for h in d.get("items",[]):
  if h["id"]!=keep and h.get("enabled"): print(h["id"])
' "$HOST_ID" | while read oid; do
  api POST "/api/v1/hosts/$oid/disable" -d '{}' >/dev/null || true
done

api PATCH "/api/v1/waf/policies/$POLICY_ID" -d "{\"name\":\"default-global\",\"enabled\":true,\"engine_mode\":\"DetectionOnly\",\"paranoia_level\":1,\"audit_relevant_only\":true}" >/dev/null
APPLY=$(api POST /api/v1/config/apply -d '{}')
echo "$APPLY" | tee /tmp/waf-apply.json | grep -q '"ok":true' || { echo "apply failed: $APPLY"; exit 1; }

CONF=$(docker exec nsp-nginx-1 cat /etc/nginx/nginx.conf)
echo "$CONF" | grep -q 'modsecurity on;' || { echo "missing modsecurity on"; exit 1; }
echo "$CONF" | grep -q 'engine-DetectionOnly.conf' || { echo "missing DetectionOnly engine file"; exit 1; }
docker exec nsp-nginx-1 grep -q 'paranoia_level=1' /var/lib/nsp/modsec/overlay.conf
docker exec nsp-nginx-1 grep -q 'bad-bots.txt' /var/lib/nsp/modsec/overlay.conf

echo "== DetectionOnly: SQLi probe not blocked (REQ-WAF-003) =="
CODE=$(curl -sS -o /tmp/waf-det.txt -w '%{http_code}' \
  -H "Host: $DOMAIN" \
  "$EDGE/?id=1'%20OR%20'1'='1")
# Upstream example.com may return 200 or redirect; must NOT be 403 from WAF
[[ "$CODE" != "403" ]] || { echo "DetectionOnly unexpectedly blocked: $CODE"; exit 1; }
echo "DetectionOnly status=$CODE (not 403)"

echo "== Blocking mode (REQ-WAF-004) =="
api PATCH "/api/v1/waf/policies/$POLICY_ID" -d "{\"name\":\"default-global\",\"enabled\":true,\"engine_mode\":\"On\",\"paranoia_level\":1,\"audit_relevant_only\":true}" >/dev/null
APPLY=$(api POST /api/v1/config/apply -d '{}')
echo "$APPLY" | grep -q '"ok":true' || { echo "blocking apply failed: $APPLY"; exit 1; }
# Reload + ModSec rule parse can lag a beat after agent returns.
for i in 1 2 3 4 5 6 7 8 9 10; do
  docker exec nsp-nginx-1 grep -q 'engine-On.conf' /etc/nginx/nginx.conf && break
  sleep 0.5
done
sleep 1
CODE=000
for i in 1 2 3 4 5; do
  CODE=$(curl -sS -o /tmp/waf-block.txt -w '%{http_code}' \
    -H "Host: $DOMAIN" \
    "$EDGE/?id=1%20UNION%20SELECT%201,2,3--")
  [[ "$CODE" == "403" ]] && break
  sleep 1
done
[[ "$CODE" == "403" ]] || { echo "expected 403 in blocking got $CODE body=$(head -c 200 /tmp/waf-block.txt)"; exit 1; }
echo "Blocking status=403 OK"

echo "== bad bot UA (REQ-RATE-004) =="
CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Host: $DOMAIN" -A "sqlmap/1.0" "$EDGE/")
[[ "$CODE" == "403" ]] || { echo "expected bad-bot 403 got $CODE"; exit 1; }

echo "== exception removes rule (REQ-WAF-007) =="
# Capture a rule id from audit if present; else use common SQLi rule 942100
RULE=942100
EX=$(api POST /api/v1/waf/exceptions -d "{\"policy_id\":\"$POLICY_ID\",\"rule_id\":\"$RULE\",\"path_prefix\":\"/\",\"reason\":\"gate fp tune\"}")
echo "$EX" | grep -q "$RULE"
api POST /api/v1/config/apply -d '{}' | grep -q '"ok":true'
docker exec nsp-nginx-1 grep -q "ruleRemoveById=$RULE\|SecRuleRemoveById $RULE" /var/lib/nsp/modsec/overlay.conf

echo "== events API + mask unit already covered (REQ-WAF-009/010) =="
# Inject a synthetic masked event via API is not available; ingest may have entries after attacks
api GET /api/v1/waf/events | grep -q items
# Wait briefly for audit ingest
sleep 2
EVENTS=$(api GET /api/v1/waf/events)
echo "$EVENTS" | grep -viq 'super-secret\|BEGIN PRIVATE' || { echo "secret in events"; exit 1; }

# Restore DetectionOnly default for lab safety
api PATCH "/api/v1/waf/policies/$POLICY_ID" -d "{\"name\":\"default-global\",\"enabled\":true,\"engine_mode\":\"DetectionOnly\",\"paranoia_level\":1,\"audit_relevant_only\":true}" >/dev/null
api POST /api/v1/config/apply -d '{}' >/dev/null || true

echo
echo "P04 WAF GATE CHECKS PASSED"
