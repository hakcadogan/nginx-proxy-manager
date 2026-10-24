#!/usr/bin/env bash
# P02 SSL gate (REQ-SSL-001/002/003/007/008/012/013, REQ-API-005).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:28080}"
ADMIN_PASS="${ADMIN_PASS:-super-secret-12}"
CK="$(mktemp)"
trap 'rm -f "$CK" /tmp/ss.pem /tmp/ss.key /tmp/ca.pem /tmp/ca.key /tmp/leaf.json /tmp/leak.json' EXIT

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

echo "== self-signed (REQ-SSL-002) =="
SS=$(api POST /api/v1/certificates/self-signed -d '{"name":"gate-ss","domains":["ssl-gate.example.com"],"valid_days":30}')
echo "$SS" | grep -q fingerprint_sha256
echo "$SS" | grep -viq 'BEGIN.*PRIVATE' || { echo "private key leaked in response"; exit 1; }
CERT_ID=$(echo "$SS" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)

echo "== private CA sign (REQ-SSL-003) =="
# Generate CA via API self-signed isn't CA — use openssl in container if available, else Go test already covers.
# Upload path: create CA with a tiny helper using docker run golang... skip if openssl missing locally.
if command -v openssl >/dev/null; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /tmp/ca.key -out /tmp/ca.pem -days 365 -nodes -subj '/CN=NSP Gate CA' 2>/dev/null
  CA_CERT=$(awk '{printf "%s\\n", $0}' /tmp/ca.pem)
  CA_KEY=$(awk '{printf "%s\\n", $0}' /tmp/ca.key)
  api POST /api/v1/certificates/private-ca -d "{\"name\":\"gate-ca-leaf\",\"domains\":[\"ca-leaf.example.com\"],\"valid_days\":30,\"ca_certificate_pem\":\"$CA_CERT\",\"ca_private_key_pem\":\"$CA_KEY\"}" \
    | grep -q fingerprint_sha256
  echo "private CA OK"
else
  echo "openssl missing — private CA covered by unit test"
fi

echo "== wildcard requires dns-01 (REQ-SSL-007) =="
CODE=$(curl -sS -o /tmp/wild.json -w '%{http_code}' -c "$CK" -b "$CK" -X POST "$BASE/api/v1/certificates/acme/issue" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -d '{"name":"wild","domains":["*.example.com"],"challenge":"http-01","staging":true}')
[[ "$CODE" == "400" ]] || { echo "expected 400 for wildcard+http-01 got $CODE $(cat /tmp/wild.json)"; exit 1; }
echo "wildcard guard OK"

echo "== ensure host + bind + TLS conf (REQ-SSL-001/012) =="
HOSTS=$(curl -sS -b "$CK" "$BASE/api/v1/hosts")
HOST_ID=$(echo "$HOSTS" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
if [[ -z "$HOST_ID" ]]; then
  api POST /api/v1/hosts -d '{"primary_domain":"ssl-gate.example.com","upstream_scheme":"http","upstream_host":"example.com","upstream_port":80,"path_prefix":"/","enabled":true,"force_https":false,"aliases":[],"custom_headers":[],"locations":[],"websocket_support":true,"access_log_enabled":true}' >/dev/null
  HOST_ID=$(curl -sS -b "$CK" "$BASE/api/v1/hosts" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
fi
# Prefer host matching cert domain
api POST "/api/v1/certificates/$CERT_ID/bind" -d "{\"host_id\":\"$HOST_ID\"}" | grep -q bound
CONF=$(docker exec nsp-nginx-1 cat /etc/nginx/nginx.conf)
echo "$CONF" | grep -q 'listen 443 ssl' || { echo "missing TLS listen"; exit 1; }
echo "$CONF" | grep -q 'ssl_protocols       TLSv1.2 TLSv1.3' || { echo "missing TLS protocol policy"; exit 1; }
echo "$CONF" | grep -q 'acme-challenge' || { echo "missing ACME challenge location"; exit 1; }
echo "TLS render OK"

echo "== key not in list response (REQ-SSL-013) =="
LIST=$(curl -sS -b "$CK" "$BASE/api/v1/certificates")
echo "$LIST" | grep -viq 'private_key\|BEGIN EC\|BEGIN RSA' || { echo "key material in list"; exit 1; }
echo "leak test OK"

echo "== renew threshold unit already in go test; list expiry fields (REQ-SSL-008/009) =="
echo "$LIST" | grep -q days_remaining
echo "$LIST" | grep -q expiring_soon

echo
echo "P02 SSL GATE CHECKS PASSED (ACME live staging optional — needs public DNS)"
