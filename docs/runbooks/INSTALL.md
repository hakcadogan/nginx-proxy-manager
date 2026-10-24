# Kurulum Runbook (P01)

1. `.env.example` → `.env`, tüm secret alanlarını değiştirin.
2. `cp .env deploy/.env` (compose çalışma dizininden okur)
3. `cd deploy && docker compose up --build -d`
4. `docker compose ps` — db, redis, nginx, api, web healthy.
5. http://localhost:28080 → bootstrap token ile ilk admin.
6. Host oluştur → Config → Validate → Apply.
7. `curl -H 'Host: your.domain' http://localhost:8088/` ile proxy’yi doğrulayın.

## Güvenlik notları

- `BOOTSTRAP_TOKEN` yalnızca ilk kurulumda; admin oluşunca endpoint reddeder.
- PostgreSQL/Redis portları host’a publish edilmez.
- Config agent `8090` host’a publish edilmez (yalnızca control network).
