# Upgrade runbook (REQ-OPS-008, REQ-QA-006)

## Önkoşullar

- Backup alındı: `GET /api/v1/backup` → güvenli arşiv
- `docs/SECURITY.md` olay prosedürü okundu
- Lab’de kuru koşum yapıldı

## Adımlar (Compose)

1. `docker compose -f deploy/docker-compose.yml pull` (veya `build`)
2. `GET /api/v1/backup` ile kontrol düzlemi yedeği
3. `docker compose up -d --build api web nginx` (db/redis aynı kalabilir)
4. Migration API açılışında otomatik (`goose`)
5. `GET /api/v1/health` ve `GET /api/v1/version` doğrula
6. `POST /api/v1/config/validate` + `apply`
7. Smoke: panel login, bir host, WAF/IDS durumu

## Rollback

1. Önceki imaj tag’ine dön
2. Gerekirse `POST /api/v1/config/rollback`
3. DB şema geri alma yalnızca down migration ile; tercihen snapshot’tan restore

## Notlar

- Private key’ler backup JSON’da yoktur; sertifika dosya volume’u ayrı yedeklenmeli
- CrowdSec hub koleksiyonları image pin’i ile gelir
