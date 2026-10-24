#!/bin/sh
set -eu

# NPM-style data dirs (bind-mounted from host repo-root data/)
mkdir -p \
  /data/logs/nginx/proxy_host \
  /data/logs/nginx/proxy_host_error \
  /data/logs/api \
  /data/logs/crowdsec \
  /data/nginx/proxy_host \
  /data/nginx/custom \
  /data/nginx/error_pages \
  /data/certs \
  /var/lib/nsp/staging \
  /var/lib/nsp/last-good \
  /var/lib/nsp/modsec \
  /var/run \
  /etc/nginx/modules \
  /etc/nginx/conf.d

# Logs/conf: world-writable for host editing.
chmod -R a+rwX /var/lib/nsp /data/logs /data/nginx 2>/dev/null || true
# Certs: API=nobody must r/w; nginx master=root opens keys (workers inherit). Host can list dirs.
chown -R nobody:nobody /data/certs 2>/dev/null || true
find /data/certs -type d -exec chmod 0755 {} \; 2>/dev/null || true
find /data/certs -name 'fullchain.pem' -exec chmod 0644 {} \; 2>/dev/null || true
find /data/certs -name 'privkey.pem' -exec chmod 0600 {} \; 2>/dev/null || true

# Compat symlink for any leftover tooling expecting /var/log/nginx
mkdir -p /var/log
ln -sfn /data/logs/nginx /var/log/nginx

# Ensure overlay exists before first nginx -t
if [ ! -f /var/lib/nsp/modsec/overlay.conf ]; then
  printf '%s\n' '# nsp overlay' > /var/lib/nsp/modsec/overlay.conf
fi
if [ ! -f /var/lib/nsp/modsec/ua-allowlist.txt ]; then
  printf '%s\n' '# nsp ua allowlist (REQ-RATE-010)' > /var/lib/nsp/modsec/ua-allowlist.txt
fi
# CRS rule catalog + version for API/UI (shared modsec volume; API has no /etc/nginx/modsec)
if [ -f /etc/nginx/modsec/crs-rules-catalog.json ]; then
  cp /etc/nginx/modsec/crs-rules-catalog.json /var/lib/nsp/modsec/crs-rules-catalog.json
fi
if [ -f /etc/nginx/modsec/crs-version.txt ]; then
  cp /etc/nginx/modsec/crs-version.txt /var/lib/nsp/modsec/crs-version.txt
fi

# proxy_host placeholder (nginx fails on empty glob); custom/ uses NPM named files only (REQ-PROXY-021)
if [ -z "$(find /data/nginx/proxy_host -maxdepth 1 -name '*.conf' 2>/dev/null | head -1)" ]; then
  printf '%s\n' '# NSP proxy_host — generated server blocks appear here after apply' \
    > /data/nginx/proxy_host/00-nsp-placeholder.conf
fi
if [ ! -f /data/nginx/custom/README.txt ]; then
  printf '%s\n' \
    'NSP custom Nginx includes (NPM-compatible names). Drop files here, then Apply config.' \
    'Only these basenames are loaded: root_top.conf root.conf http_top.conf http.conf' \
    'events.conf stream.conf server_proxy.conf server_dead.conf' \
    '(server_redirect / server_stream* reserved until those host types exist.)' \
    'No UI editor — operator volume only. Broken snippets fail nginx -t and roll back.' \
    > /data/nginx/custom/README.txt
fi

# Default HTML error pages (REQ-PROXY-022) — seed missing files only (keep operator edits)
if [ -d /etc/nginx/nsp-error-pages ]; then
  for f in /etc/nginx/nsp-error-pages/*; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    if [ ! -f "/data/nginx/error_pages/$base" ]; then
      cp "$f" "/data/nginx/error_pages/$base"
    fi
  done
fi

# CRS setup from example if missing
if [ -f /opt/owasp-crs/crs-setup.conf.example ] && [ ! -f /opt/owasp-crs/crs-setup.conf ]; then
  cp /opt/owasp-crs/crs-setup.conf.example /opt/owasp-crs/crs-setup.conf
fi

# Unicode map fallback
if [ ! -f /etc/nginx/modsec/unicode.mapping ] && [ -f /etc/modsecurity.d/unicode.mapping ]; then
  ln -sf /etc/modsecurity.d/unicode.mapping /etc/nginx/modsec/unicode.mapping
fi

# Minimal always-on health endpoint for container healthcheck (until first apply).
cat >/etc/nginx/conf.d/healthz.conf <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    access_log /data/logs/nginx/fallback_access.log;
    error_log /data/logs/nginx/fallback_error.log warn;
    location = /healthz { return 200 'ok'; add_header Content-Type text/plain; }
}
EOF

# Keep a pristine baseline copy for emergency fallback.
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.baseline

# Baseline must load ModSecurity module if present.
if [ -f /etc/nginx/modules/ngx_http_modsecurity_module.so ]; then
  if ! grep -q 'ngx_http_modsecurity_module' /etc/nginx/nginx.conf; then
    conf=$(cat /etc/nginx/nginx.conf)
    printf 'load_module modules/ngx_http_modsecurity_module.so;\n%s\n' "$conf" > /etc/nginx/nginx.conf
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.baseline
  fi
fi

# Start config-agent in background (control network only via compose).
CONFIG_AGENT_TOKEN="${CONFIG_AGENT_TOKEN:?CONFIG_AGENT_TOKEN required}" \
HTTP_ADDR=":8090" \
NGINX_LIVE_CONF="/etc/nginx/nginx.conf" \
NGINX_LAST_GOOD_DIR="/var/lib/nsp/last-good" \
/usr/local/bin/config-agent &

# Prefer last-good live conf (has upstreams matching proxy_host/*.conf). Baseline alone
# cannot boot after an apply because host files reference pool/upstream names.
if [ -f /var/lib/nsp/last-good/nginx.conf ]; then
  cp /var/lib/nsp/last-good/nginx.conf /etc/nginx/nginx.conf
else
  cp /etc/nginx/nginx.conf /var/lib/nsp/last-good/nginx.conf
fi

export LD_LIBRARY_PATH="/usr/local/modsecurity/lib:${LD_LIBRARY_PATH:-}"

# If last-good fails nginx -t (e.g. stale host files), fall back to baseline + empty hosts.
if ! nginx -t -c /etc/nginx/nginx.conf >/tmp/nginx-t.out 2>&1; then
  echo "nsp: last-good nginx -t failed; using baseline + placeholder hosts" >&2
  cat /tmp/nginx-t.out >&2 || true
  # keep a copy of broken conf for debug
  cp /etc/nginx/nginx.conf /var/lib/nsp/last-good/nginx.conf.broken 2>/dev/null || true
  # restore image baseline (re-copied below from /etc/nginx/nginx.conf.bak if we saved it)
  if [ -f /etc/nginx/nginx.conf.baseline ]; then
    cp /etc/nginx/nginx.conf.baseline /etc/nginx/nginx.conf
  fi
  # neutralize host includes so baseline can start
  find /data/nginx/proxy_host -maxdepth 1 -type f -name '*.conf' ! -name '00-nsp-placeholder.conf' \
    -exec mv {} {}.disabled \; 2>/dev/null || true
  printf '%s\n' '# NSP proxy_host — waiting for apply' > /data/nginx/proxy_host/00-nsp-placeholder.conf
  nginx -t -c /etc/nginx/nginx.conf || true
fi

exec nginx -g 'daemon off;'
