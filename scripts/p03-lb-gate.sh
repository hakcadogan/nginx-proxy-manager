#!/usr/bin/env bash
# P03 LB gate (REQ-LB-001..011, REQ-PROXY-012, REQ-API-006).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:28080}"
ADMIN_PASS="${ADMIN_PASS:-super-secret-12}"
CK="$(mktemp)"
trap 'rm -f "$CK" /tmp/lb-*.json' EXIT

echo "== unit: LB render golden =="
(cd "$ROOT/apps/api" && go test ./internal/nginxcfg/ -count=1 -run 'TestLB|TestRejectBlocked')

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

echo "== create pool + members (REQ-LB-001/003/009) =="
POOL=$(api POST /api/v1/upstreams -d '{
  "name":"gate-pool-'"$(date +%s)"'",
  "algorithm":"least_conn",
  "scheme":"http",
  "max_fails":2,
  "fail_timeout":"5s",
  "connect_timeout":"4s",
  "send_timeout":"20s",
  "read_timeout":"20s",
  "health_check_enabled":false
}')
echo "$POOL" > /tmp/lb-pool.json
POOL_ID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' /tmp/lb-pool.json | head -1)
[[ -n "$POOL_ID" ]] || { echo "no pool id: $POOL"; exit 1; }

# Use publicly resolvable hosts — nginx resolves upstream names at reload time.
api POST "/api/v1/upstreams/$POOL_ID/members" -d '{"host":"example.com","port":80,"weight":3}' >/tmp/lb-m1.json
api POST "/api/v1/upstreams/$POOL_ID/members" -d '{"host":"www.example.com","port":80,"weight":1,"is_backup":true}' >/tmp/lb-m2.json
M1=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' /tmp/lb-m1.json | head -1)

echo "== SSRF blocklist on member (RISK-09) =="
CODE=$(curl -sS -o /tmp/lb-ssrf.json -w '%{http_code}' -c "$CK" -b "$CK" -X POST "$BASE/api/v1/upstreams/$POOL_ID/members" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -d '{"host":"169.254.169.254","port":80,"weight":1}')
[[ "$CODE" == "400" ]] || { echo "expected 400 for metadata host got $CODE"; exit 1; }

echo "== drain member (REQ-LB-011) =="
api PATCH "/api/v1/upstreams/$POOL_ID/members/$M1" -d '{"host":"example.com","port":80,"weight":3,"is_drain":true}' >/tmp/lb-drain.json
grep -q '"is_drain":true' /tmp/lb-drain.json

echo "== bind host to pool + apply =="
DOMAIN="lb-gate-$(date +%s).example.com"
HOST=$(api POST /api/v1/hosts -d "{
  \"primary_domain\":\"$DOMAIN\",
  \"upstream_scheme\":\"http\",
  \"upstream_host\":\"pool.local\",
  \"upstream_port\":80,
  \"upstream_id\":\"$POOL_ID\",
  \"path_prefix\":\"/\",
  \"enabled\":true,
  \"aliases\":[],
  \"custom_headers\":[],
  \"locations\":[],
  \"websocket_support\":true,
  \"access_log_enabled\":true
}")
echo "$HOST" | grep -q "$DOMAIN"
HOST_ID=$(echo "$HOST" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
# Lab isolation: disable other hosts so unresolved leftover upstreams don't break nginx -t
curl -sS -b "$CK" "$BASE/api/v1/hosts" | python3 -c '
import json,sys
d=json.load(sys.stdin)
keep=sys.argv[1]
for h in d.get("items",[]):
  if h["id"]!=keep and h.get("enabled"):
    print(h["id"])
' "$HOST_ID" | while read oid; do
  api POST "/api/v1/hosts/$oid/disable" -d '{}' >/dev/null || true
done

APPLY=$(api POST /api/v1/config/apply -d '{}')
echo "$APPLY" | tee /tmp/lb-apply.json | grep -q '"ok":true' || { echo "apply failed: $APPLY"; exit 1; }

echo "== nginx conf asserts (REQ-LB-004/007/009/010/011) =="
CONF=$(docker exec nsp-nginx-1 cat /etc/nginx/nginx.conf)
echo "$CONF" | grep -q 'least_conn;' || { echo "missing least_conn"; exit 1; }
echo "$CONF" | grep -q 'example.com:80' || { echo "missing member a"; exit 1; }
echo "$CONF" | grep -q 'backup' || { echo "missing backup"; exit 1; }
echo "$CONF" | grep -q ' down;' || { echo "missing drain/down"; exit 1; }
echo "$CONF" | grep -q 'max_fails=2 fail_timeout=5s' || { echo "missing passive health"; exit 1; }
echo "$CONF" | grep -q 'proxy_connect_timeout 4s;' || { echo "missing connect timeout"; exit 1; }
echo "$CONF" | grep -q 'proxy_next_upstream' || { echo "missing next_upstream"; exit 1; }

echo "== health endpoint (REQ-LB-008 surface) =="
api GET "/api/v1/upstreams/$POOL_ID/health" | grep -q members

echo
echo "P03 LB GATE CHECKS PASSED"
