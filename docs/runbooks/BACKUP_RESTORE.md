# Backup / restore (REQ-OBS-004/005, REQ-DATA-007, REQ-API-014)

## Export

```bash
curl -fsS -b cookies.txt -H "X-CSRF-Token: $CSRF" \
  http://localhost:28080/api/v1/backup -o nsp-backup.json
```

İçerik: host’lar, upstream’ler, sertifika **meta**, WAF/IP politikaları, platform ayarları, son applied config özeti.  
**Private key / ACME secret dahil değildir.**

## DB dump (tam tutarlılık)

```bash
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U nsp nsp > nsp-db.sql
```

## Restore (lab)

1. Temiz ortamda compose ayağa kaldır
2. `psql` ile `nsp-db.sql` yükle **veya** migration + settings restore:
   `POST /api/v1/backup/restore` (settings + host JSON referansı)
3. Cert volume’u geri kopyala
4. `POST /api/v1/config/apply`

## Retention

`POST /api/v1/ops/retention` — audit / security_events / eski config sürümleri.
