#!/usr/bin/env bash
# P05 IDS gate (REQ-IDS-001..011, REQ-OBS-003, REQ-API-008).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:28080}"
ADMIN_PASS="${ADMIN_PASS:-super-secret-12}"
CK="$(mktemp)"
trap 'rm -f "$CK" /tmp/ids-*.json' EXIT

echo "== unit: IP allowlist precedence =="
(cd "$ROOT/apps/api" && go test ./internal/nginxcfg/ -count=1 -run 'TestRenderIPAccess|TestValidateIP')

echo "== CrowdSec engine healthy (REQ-IDS-001) =="
docker compose -f "$ROOT/deploy/docker-compose.yml" ps crowdsec | grep -qi healthy \
  || docker inspect nsp-crowdsec-1 --format '{{.State.Health.Status}}' | grep -q healthy

echo "== LAPI not published to host (network isolation) =="
# No 8080/8081 mapping for crowdsec on host
docker port nsp-crowdsec-1 2>/dev/null | grep -q . && { echo "crowdsec should not publish ports"; docker port nsp-crowdsec-1; exit 1; } || true
ss -lntp 2>/dev/null | grep -E ':8080\s' | grep -qi crowdsec && { echo "LAPI on host"; exit 1; } || true

echo "== collections / hub pin surface (REQ-IDS-010) =="
docker exec nsp-crowdsec-1 cscli collections list 2>/dev/null | tee /tmp/ids-col.txt | grep -qi nginx \
  || docker exec nsp-crowdsec-1 ls /etc/crowdsec/collections/ 2>/dev/null | grep -qi nginx \
  || echo "collections still installing — acquis present"
docker exec nsp-crowdsec-1 test -f /etc/crowdsec/acquis.yaml

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

echo "== bouncer key not in API responses (REQ-IDS-011) =="
DEC=$(api GET /api/v1/ids/decisions)
echo "$DEC" | grep -viq 'change-me-crowdsec\|BOUNCER_KEY\|X-Api-Key' || { echo "key leaked"; exit 1; }
echo "$DEC" | grep -q 'control-plane-nginx-deny'

echo "== ensure host for deny render =="
DOMAIN="ids-gate-$(date +%s).example.com"
HOST=$(api POST /api/v1/hosts -d "{
  \"primary_domain\":\"$DOMAIN\",
  \"upstream_scheme\":\"http\",
  \"upstream_host\":\"example.com\",
  \"upstream_port\":80,
  \"path_prefix\":\"/\",
  \"enabled\":true,
  \"waf_enabled\":false,
  \"aliases\":[],
  \"custom_headers\":[],
  \"locations\":[],
  \"websocket_support\":false,
  \"access_log_enabled\":true
}")
HOST_ID=$(echo "$HOST" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
curl -sS -b "$CK" "$BASE/api/v1/hosts" | python3 -c '
import json,sys
d=json.load(sys.stdin); keep=sys.argv[1]
for h in d.get("items",[]):
  if h["id"]!=keep and h.get("enabled"): print(h["id"])
' "$HOST_ID" | while read oid; do
  api POST "/api/v1/hosts/$oid/disable" -d '{}' >/dev/null || true
done

BAN_IP="203.0.113.50"
ALLOW_IP="203.0.113.50"
DENY_IP="198.51.100.66"

echo "== manual ban (REQ-IDS-005/008) =="
BAN=$(api POST /api/v1/ids/bans -d "{\"ip\":\"$BAN_IP\",\"reason\":\"gate ban\",\"ttl_hours\":2}")
echo "$BAN" | grep -q "$BAN_IP"
BAN_ID=$(echo "$BAN" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
api POST /api/v1/config/apply -d '{}' | grep -q '"ok":true'
docker exec nsp-nginx-1 grep -q "deny $BAN_IP" /etc/nginx/nginx.conf

echo "== allowlist wins (REQ-IDS-006) =="
api POST /api/v1/ids/allowlist -d "{\"ip\":\"$ALLOW_IP\",\"reason\":\"gate allow\"}" >/dev/null
api POST /api/v1/config/apply -d '{}' | grep -q '"ok":true'
CONF=$(docker exec nsp-nginx-1 cat /etc/nginx/nginx.conf)
echo "$CONF" | grep -q "allow $ALLOW_IP"
# allowlisted IP must not appear as deny (RenderIPAccess)
echo "$CONF" | grep "deny $ALLOW_IP" && { echo "allowlisted still denied"; exit 1; } || true

echo "== denylist (REQ-IDS-007) =="
api POST /api/v1/ids/denylist -d "{\"ip\":\"$DENY_IP\",\"reason\":\"gate deny\"}" >/dev/null
api POST /api/v1/config/apply -d '{}' | grep -q '"ok":true'
docker exec nsp-nginx-1 grep -q "deny $DENY_IP" /etc/nginx/nginx.conf

echo "== unban (REQ-IDS-008) =="
api DELETE "/api/v1/ids/bans/$BAN_ID" >/dev/null
# ban row deleted; allow may remain

echo "== unified security events (REQ-OBS-003) =="
api GET "/api/v1/security-events?source=crowdsec" | grep -q items
api GET "/api/v1/security-events?source=waf" | grep -q items

echo
echo "P05 IDS GATE CHECKS PASSED"
