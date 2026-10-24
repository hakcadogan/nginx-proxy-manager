# Nginx Security Platform (NSP)

Self-hosted Nginx reverse proxy, load balancer and web security control plane.

**Aktif aşama:** Phase 01 MVP (`plans/PHASE_01_MVP.md`)

## Hızlı kurulum (REQ-QA-005)

### Gereksinimler

- Docker + Docker Compose
- (geliştirme) Go 1.22+, Node 22+

### Adımlar

```bash
cp .env.example .env
# .env içindeki parolaları ve token'ları güçlendirin

cd deploy
docker compose up --build -d
```

- Yönetim paneli: http://localhost:28080 (`WEB_PORT`, varsayılan 28080)  
- Veri düzlemi Nginx: http://localhost:8088  
- İlk giriş: panelde bootstrap (`.env` içindeki `BOOTSTRAP_TOKEN`) + admin e-posta/parola (min 12 karakter)

```bash
# compose, repo kökündeki .env ile:
cp .env.example .env   # secret'ları değiştirin
cp .env deploy/.env
cd deploy && docker compose up --build -d
```

### Mimari kilitler (P01)

- Oturum: HttpOnly cookie + CSRF (`X-CSRF-Token`)
- Config agent: ayrı binary, Docker socket **yok**
- Redis: session için zorunlu
- Raw nginx snippet: kapalı

### Geliştirme testleri

```bash
cd apps/api && go test ./...
./scripts/check-traceability.sh
./scripts/p01-gate.sh          # P01 kapı (compose ayaktayken)
cd apps/web && npm run test:e2e
```

### Dokümanlar

| Dosya | İçerik |
|-------|--------|
| `AGENTS.md` | Ajan çalışma kuralları |
| `docs/REQUIREMENTS.md` | Gereksinim kataloğu |
| `docs/ARCHITECTURE.md` | Mimari |
| `docs/SECURITY.md` | Güvenlik |
| `plans/MASTER_PLAN.md` | Aşamalar |

Uygulama koduna başlarken `AGENTS.md` zorunluluklarına uyun.
