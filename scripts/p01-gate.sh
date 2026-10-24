#!/usr/bin/env bash
# P01 aşama kapısı doğrulama (REQ-CFG-002, REQ-CFG-005, REQ-AUTH-003/004, REQ-QA-*).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
BASE="${BASE_URL:-http://localhost:28080}"
AGENT_TOKEN="$(grep -E '^CONFIG_AGENT_TOKEN=' "$ROOT/deploy/.env" | cut -d= -f2-)"
CK="$(mktemp)"
trap 'rm -f "$CK" /tmp/viewer-del.json /tmp/chaos.json /tmp/neg.json' EXIT

echo "== health =="
"${COMPOSE[@]}" ps
curl -fsS "$BASE/api/v1/health" >/dev/null

echo "== login admin =="
ADMIN_PASS="${ADMIN_PASS:-super-secret-12}"
LOGIN=$(curl -sS -c "$CK" -b "$CK" -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@example.com\",\"password\":\"$ADMIN_PASS\"}")
echo "$LOGIN" | grep -q csrf_token || { echo "admin login failed: $LOGIN" >&2; exit 1; }
CSRF=$(grep nsp_csrf "$CK" | awk '{print $7}')

api() {
  local method=$1 path=$2
  shift 2
  curl -sS -c "$CK" -b "$CK" -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" "$@"
}

echo "== create viewer (REQ-AUTH-003) =="
VIEWER_EMAIL="viewer-$(date +%s)@example.com"
api POST /api/v1/users -d "{\"email\":\"$VIEWER_EMAIL\",\"password\":\"viewer-secret-12\",\"role\":\"viewer\"}" \
  | grep -q '"role":"viewer"'

echo "== viewer cannot delete host (403) =="
HOST_ID=$(curl -sS -b "$CK" "$BASE/api/v1/hosts" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
if [[ -z "$HOST_ID" ]]; then
  api POST /api/v1/hosts -d '{"primary_domain":"gate.example.com","upstream_scheme":"http","upstream_host":"example.com","upstream_port":80,"path_prefix":"/","enabled":true,"aliases":[],"custom_headers":[],"locations":[],"websocket_support":true,"access_log_enabled":true}' >/dev/null
  HOST_ID=$(curl -sS -b "$CK" "$BASE/api/v1/hosts" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
fi
VCK="$(mktemp)"
curl -sS -c "$VCK" -b "$VCK" -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$VIEWER_EMAIL\",\"password\":\"viewer-secret-12\"}" >/dev/null
VCSRF=$(grep nsp_csrf "$VCK" | awk '{print $7}')
CODE=$(curl -sS -o /tmp/viewer-del.json -w '%{http_code}' -b "$VCK" -X DELETE "$BASE/api/v1/hosts/$HOST_ID" \
  -H "X-CSRF-Token: $VCSRF")
rm -f "$VCK"
[[ "$CODE" == "403" ]] || { echo "expected 403 got $CODE"; cat /tmp/viewer-del.json; exit 1; }
echo "viewer delete → 403 OK"

echo "== nginx -t negative fixture (REQ-CFG-002) =="
docker cp "$ROOT/testdata/nginxcfg/invalid.conf" nsp-nginx-1:/var/lib/nsp/staging/nginx.conf
NEG_CODE=$(docker exec nsp-nginx-1 curl -s -o /tmp/neg.json -w '%{http_code}' \
  -H "X-Agent-Token: $AGENT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"staging_conf":"/var/lib/nsp/staging/nginx.conf"}' \
  http://127.0.0.1:8090/v1/validate)
NEG_BODY=$(docker exec nsp-nginx-1 cat /tmp/neg.json)
echo "validate status=$NEG_CODE body=$NEG_BODY"
[[ "$NEG_CODE" == "422" ]] || { echo "expected 422 for invalid conf"; exit 1; }
echo "invalid conf rejected OK"

echo "== restore valid staging + apply =="
api POST /api/v1/config/apply -d '{}' | grep -q '"ok":true'

echo "== reload chaos rollback (REQ-CFG-005) =="
BEFORE=$(docker exec nsp-nginx-1 sha256sum /etc/nginx/nginx.conf | awk '{print $1}')
docker exec nsp-nginx-1 curl -s -H "X-Agent-Token: $AGENT_TOKEN" -H 'Content-Type: application/json' \
  -d '{}' -X POST http://127.0.0.1:8090/v1/chaos/fail-next-reload | grep -q '"ok":true'
CHAOS_CODE=$(curl -sS -o /tmp/chaos.json -w '%{http_code}' -c "$CK" -b "$CK" -X POST "$BASE/api/v1/config/apply" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" -d '{}')
echo "chaos apply http=$CHAOS_CODE body=$(cat /tmp/chaos.json)"
[[ "$CHAOS_CODE" == "409" ]] || { echo "expected 409 on chaos reload"; exit 1; }
AFTER=$(docker exec nsp-nginx-1 sha256sum /etc/nginx/nginx.conf | awk '{print $1}')
[[ "$BEFORE" == "$AFTER" ]] || { echo "live conf changed after failed reload (rollback broken)"; exit 1; }
curl -fsS http://localhost:8088/healthz | grep -q ok
echo "chaos rollback OK (live conf preserved)"

docker exec nsp-nginx-1 rm -f /var/lib/nsp/chaos-fail-reload || true
api POST /api/v1/config/apply -d '{}' | grep -q '"ok":true'

echo
echo "P01 GATE CHECKS PASSED"
