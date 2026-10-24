# NSP data layout (Nginx Proxy Manager–style)

Host bind-mounts live under repo-root `data/` (gitignored except this README).
Compose (`deploy/docker-compose.yml`) mounts them as `../data/...`.

```
data/
  logs/
    nginx/
      proxy_host/          # per-host access logs (*.log, *.ssl.log)
      proxy_host_error/    # per-host error logs
      error.log            # global error log
      fallback_access.log
      fallback_error.log
      modsec_audit.log
    api/
    crowdsec/
  nginx/
    proxy_host/            # generated server blocks (do not edit by hand)
    custom/                # NPM named includes (see custom/README.txt)
  certs/
    <certificate-uuid>/
      fullchain.pem
      privkey.pem          # mode 0600 — do not commit
  crowdsec/
    overrides/             # CrowdSec local overrides
```

Create dirs once:

```bash
mkdir -p data/logs/nginx/proxy_host data/logs/nginx/proxy_host_error \
  data/logs/api data/logs/crowdsec \
  data/nginx/proxy_host data/nginx/custom data/certs \
  data/crowdsec/overrides
```

Or start the stack — entrypoints create missing paths.

TLS material is bind-mounted at `/data/certs` (and `/var/lib/nsp/certs` for path compatibility). ACME account keys stay in the `nginx_conf_state` volume.
