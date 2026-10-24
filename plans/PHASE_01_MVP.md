# PHASE_01_MVP — Nginx, API, Panel, Proxy CRUD, Güvenli Config

**Durum:** GATE PASSED (yeniden doğrulandı 2026-10-22)  
**Önkoşul:** Yok (ilk aşama)  
**Sonraki:** `PHASE_02_SSL.md` (bu oturumda geçilmedi)  
**Hedef:** Çalışan kontrol düzlemi + temel reverse proxy veri düzlemi; conf validate/apply/rollback.

## 1. Kapsam özeti

- Docker Compose: `web`, `api`, `db`, `redis`, `nginx` (+ mevcut stack’te sonraki aşama servisleri)
- Go REST API `/api/v1` + OpenAPI
- React+TS panel, TR/EN
- Proxy host CRUD, rate/connection limit temelleri
- Config render → `nginx -t` → reload → rollback
- Auth: kullanıcı, session, RBAC (Admin/Operator/Viewer), audit
- Unit/integration/E2E + kurulum dokümanı

## 2. Sahiplenilen gereksinimler

### Proxy (11)
`REQ-PROXY-001`, `REQ-PROXY-002`, `REQ-PROXY-003`, `REQ-PROXY-004`, `REQ-PROXY-005`, `REQ-PROXY-006`, `REQ-PROXY-007`, `REQ-PROXY-008`, `REQ-PROXY-009`, `REQ-PROXY-010`, `REQ-PROXY-011`

### Rate (3)
`REQ-RATE-001`, `REQ-RATE-002`, `REQ-RATE-003`

### API (7)
`REQ-API-001`, `REQ-API-002`, `REQ-API-003`, `REQ-API-004`, `REQ-API-009`, `REQ-API-010`, `REQ-API-011`

### UI (6)
`REQ-UI-001`, `REQ-UI-002`, `REQ-UI-003`, `REQ-UI-004`, `REQ-UI-011`, `REQ-UI-012`

### Data (5)
`REQ-DATA-001`, `REQ-DATA-002`, `REQ-DATA-003`, `REQ-DATA-004`, `REQ-DATA-005`

### Auth (6)
`REQ-AUTH-001`, `REQ-AUTH-002`, `REQ-AUTH-003`, `REQ-AUTH-004`, `REQ-AUTH-005`, `REQ-AUTH-009`

### Config (10)
`REQ-CFG-001`, `REQ-CFG-002`, `REQ-CFG-003`, `REQ-CFG-004`, `REQ-CFG-005`, `REQ-CFG-006`, `REQ-CFG-007`, `REQ-CFG-008`, `REQ-CFG-009`, `REQ-CFG-010`

### Ops (6)
`REQ-OPS-001`, `REQ-OPS-002`, `REQ-OPS-003`, `REQ-OPS-004`, `REQ-OPS-005`, `REQ-OPS-006`

### Obs / QA (7)
`REQ-OBS-002`, `REQ-QA-001`, `REQ-QA-002`, `REQ-QA-003`, `REQ-QA-004`, `REQ-QA-005`, `REQ-QA-009`

**Bu aşamada sahiplenilen REQ sayısı:** 61

## 3. Bilinçli olarak dışı

- ACME / Let’s Encrypt (P02)
- LB algoritmaları ve pool UI (P03)
- ModSecurity (P04) — P01 kabulü için host’ta `waf_enabled=false` ile doğrulandı
- CrowdSec (P05)
- MFA, backup API, Prometheus (P06)

## 4. Görev kırılımı

| # | Görev | REQ | Durum |
|---|-------|-----|-------|
| 1.1 | Repo iskeleti | OPS/QA | DONE |
| 1.2 | Compose stack | OPS-001…006 | VERIFIED |
| 1.3 | Postgres migration | DATA-001,005 | VERIFIED |
| 1.4 | Auth bootstrap + RBAC | AUTH-* | VERIFIED |
| 1.5 | Hosts CRUD API | PROXY/API-003 | VERIFIED |
| 1.6 | Rate limit profil | RATE-001…003,007…009 | VERIFIED |
| 1.7 | Template + golden | CFG-001,008 | VERIFIED |
| 1.8 | Validate/apply/rollback | CFG-002…007,010 | VERIFIED |
| 1.9 | Audit + JSON log | DATA-003, API-011 | VERIFIED |
| 1.10 | React i18n | UI-001,002 | VERIFIED |
| 1.11 | Hosts + config UI | UI-003,004 | VERIFIED |
| 1.12 | OpenAPI + CI | API-002, QA-* | VERIFIED |
| 1.13 | Kurulum docs | QA-005 | VERIFIED |

## 5. Mimari kararlar (kilitli)

1. Oturum: **cookie + CSRF** (JWT değil).
2. Config agent: **ayrı binary**, shared volume; Docker socket yok.
3. Raw nginx snippet: **kapalı**.
4. Redis: session için **zorunlu**.

## 6. Kabul kriterleri (aşama kapısı) — 2026-10-22 yeniden koşum

- [x] `compose up` sonrası healthcheck yeşil
- [x] Admin login → host oluştur → apply → gerçek backend’e proxy (`NSP_P01_BACKEND_OK` via `:8088` Host)
- [x] Metadata upstream (`169.254.169.254`) API’de 400
- [x] Bozuk conf `nginx -t` → 422; live conf checksum korunur
- [x] Reload chaos → 409 + rollback (`scripts/p01-gate.sh`)
- [x] Viewer host silemez (403)
- [x] Playwright E2E yeşil (`apps/web/e2e/smoke.spec.ts` — `/hosts` rotası)
- [x] `go test ./...` yeşil; traceability OK

## 7. Doğrulama kanıtı (bu oturum)

| Test | Sonuç |
|------|-------|
| `go test ./...` | PASS |
| `scripts/check-traceability.sh` | PASS |
| `scripts/p01-gate.sh` | PASS |
| Gerçek trafik → `hashicorp/http-echo` | PASS (200 + body) |
| Invalid conf apply / live preserve | PASS (422, checksum aynı, trafik sürer) |
| Playwright smoke | PASS (1/1) |
| `REQ-OBS-002` host bind logs | VERIFIED (`data/logs/nginx` + `proxy_host/*.log`; panel export yok) |

## 8. Notlar / risk

- Compose’ta P02–P06 servisleri de bulunabilir; bu oturum **yalnızca P01 kabulünü** yeniden doğruladı, diğer aşamalara geçilmedi.
- Yoğun CrowdSec deny listesi + reload anında host `:8088` kısa süre empty-reply verebilir; kararlı worker’larla trafik OK. P01 trafiği için ACL temizliği / WAF off kullanıldı.
- E2E: ana sayfa dashboard olduğu için smoke testi `/hosts` linkine yönlendirildi.

## 9. Çıkış

P01 kapısı yeşil. Kullanıcı onayı olmadan P02+ uygulanmadı.
