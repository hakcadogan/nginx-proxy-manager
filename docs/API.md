# API.md — Go REST API Sözleşmesi (Taslak)

**Versiyon:** 1.0.0-draft  
**Base path:** `/api/v1`  
**OpenAPI:** geliştirmede `api/openapi.yaml` (REQ-API-002) — henüz kod yok  
**Auth:** Session cookie veya Bearer (P01’de netleştirilir)

Bu belge uygulama öncesi **sözleşme iskeletidir**. Kesin şemalar OpenAPI’de yaşar; burada kaynak grupları, aşama eşlemesi ve güvenlik notları tutulur.

## Ortak kurallar

| Konu | Kural |
|------|-------|
| Content-Type | `application/json` |
| Hata formatı | `{ "error": { "code", "message", "details?" } }` |
| Sayfalama | `page`, `per_page` veya cursor |
| İdempotency | Kritik apply/issue için `Idempotency-Key` (P06 zorunlu, P01 önerilir) |
| Audit | Tüm mutasyonlar auditlenir |
| Secrets | Response’ta private key / raw token yok |

## Health (auth yok)

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET | `/health` | P01 | REQ-API-001 |
| GET | `/version` | P01 | REQ-API-001 |
| GET | `/metrics` | P06 | REQ-OBS-001 |

## Auth

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| POST | `/auth/login` | P01 | REQ-API-009, REQ-AUTH-002 |
| POST | `/auth/logout` | P01 | REQ-API-009 |
| POST | `/auth/refresh` | P01 | REQ-API-009 |
| GET | `/auth/me` | P01 | REQ-AUTH-003 |
| POST | `/auth/bootstrap` | P01 | REQ-AUTH-005 |

## Proxy hosts

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET | `/hosts` | P01 | REQ-API-003 |
| POST | `/hosts` | P01 | REQ-API-003 |
| GET | `/hosts/{id}` | P01 | REQ-API-003 |
| PATCH | `/hosts/{id}` | P01 | REQ-API-003 |
| DELETE | `/hosts/{id}` | P01 | REQ-API-003 |
| POST | `/hosts/{id}/enable` | P01 | REQ-PROXY-010 |
| POST | `/hosts/{id}/disable` | P01 | REQ-PROXY-010 |
| POST | `/hosts/{id}/probe` | P06 | REQ-PROXY-020 |
| GET | `/settings/network` | P06 | REQ-PROXY-019 |
| PUT | `/settings/network` | P06 | REQ-PROXY-019 |
| GET/PUT | `/settings/logs` | P06 | REQ-OBS-006 | log rotate enabled/max_mb/keep/interval |
| POST | `/ops/log-rotate` | P06 | REQ-OBS-006 | `?force=1` — boyut aşan `*.log` döndür + nginx reopen |

## Config lifecycle

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| POST | `/config/validate` | P01 | REQ-CFG-009, REQ-API-004 |
| POST | `/config/apply` | P01 | REQ-CFG-003, REQ-API-004 |
| GET | `/config/versions` | P01 | REQ-CFG-004 |
| GET | `/config/versions/{id}` | P01 | REQ-CFG-004 |
| POST | `/config/rollback` | P01 | REQ-CFG-005/006 |
| GET | `/config/status` | P01 | REQ-API-004 |

## Certificates (SSL)

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET | `/certificates` | P02 | REQ-API-005 |
| POST | `/certificates/upload` | P02 | REQ-SSL-001 |
| POST | `/certificates/self-signed` | P02 | REQ-SSL-002 |
| POST | `/certificates/acme/issue` | P02 | REQ-SSL-004/005 |
| POST | `/certificates/{id}/renew` | P02 | REQ-SSL-008 |
| DELETE | `/certificates/{id}` | P02 | REQ-API-005 |

## Upstream / LB

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET/POST | `/upstreams` | P03 | REQ-API-006, REQ-LB-001 |
| GET/PATCH/DELETE | `/upstreams/{id}` | P03 | REQ-LB-001 |
| POST | `/upstreams/{id}/members` | P03 | REQ-LB-001 |
| PATCH | `/upstreams/{id}/members/{mid}` | P03 | REQ-LB-011 |
| GET | `/upstreams/{id}/health` | P03 | REQ-LB-007/008 |

## WAF

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET/PATCH | `/waf/policies` | P04 | REQ-API-007 |
| GET/POST/PATCH/DELETE | `/waf/exceptions` | P04 | REQ-WAF-007 | PATCH `{id}`: rule_id, path, arg, reason, host_id, enabled |
| GET | `/waf/crs-rules` | P04 | REQ-WAF-007 | CRS katalog; `q`/`category`/`enabled`/`page` |
| PATCH | `/waf/crs-rules/{id}` | P04 | REQ-WAF-007 | `{ "enabled": true\|false }` → SecRuleRemoveById |
| GET/PUT | `/waf/ua-allowlist` | P04 | REQ-RATE-010 | `{ patterns: string[] }` — bad-bot kuralı istisnası |
| GET/PUT | `/waf/ip-allowlist` | P06 | REQ-WAF-019 | `{ entries: string[] }` — IP/CIDR; ModSec `ruleEngine=Off` |
| GET/PUT | `/waf/modsec-settings` | P04 | REQ-WAF-017 | allowlist audit/debug/body ayarları |
| GET/PUT | `/waf/custom-rules` | P04 | REQ-WAF-018 | `{ global, hosts: { host_id: text } }` |
| GET | `/waf/events` | P04 | REQ-WAF-009 | `q` (msg/uri/payload/ip), `client_ip`, `rule_id`, `domain`, `source` |
| GET | `/waf/events/{id}` | P04 | REQ-WAF-010 |

## IDS / IP policies

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET | `/ids/decisions` | P05 | REQ-IDS-009 |
| POST | `/ids/bans` | P05 | REQ-IDS-005 |
| DELETE | `/ids/bans/{id}` | P05 | REQ-IDS-008 |
| GET/POST/DELETE | `/ids/allowlist` | P05 | REQ-IDS-006 |
| GET/POST/DELETE | `/ids/denylist` | P05 | REQ-IDS-007 |
| POST | `/ids/policies/bulk-create` | P05 | REQ-IDS-018 | `{ kind, reason, ttl_hours?, ips[] }` — ortak gerekçe, tek apply |
| POST | `/ids/policies/bulk-delete` | P05 | REQ-IDS-008 | `{ "ids": ["uuid",…] }` — tek apply |
| GET | `/ids/protected` | P05 | REQ-IDS-014 | |
| PUT | `/ids/protected` | P05 | REQ-IDS-014 | `{ "protected_cidrs": "…" }` |
| GET | `/ids/detection` | P05 | REQ-IDS-017 | `{ settings, agent_ok, hints }` |
| PUT | `/ids/detection` | P05 | REQ-IDS-017 | allowlist alanlar → scenario/profile override + agent apply |
| GET/PUT | `/ids/enforcement` | P05 | REQ-IDS-019 | `active` \| `passive` — pasifte nginx deny yok |

## Rate limit profiles

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET/POST/PATCH | `/rate-limits` | P01 | REQ-RATE-001/003 |

## Users / RBAC (P06 sertleştirme; okuma P01)

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET/POST | `/users` | P01/P06 | REQ-AUTH-003, REQ-UI-009 |
| PATCH/DELETE | `/users/{id}` | P06 | REQ-AUTH-003 |
| GET | `/roles` | P01 | REQ-AUTH-004 |

## Audit / logs / backup

| Method | Path | Aşama | REQ |
|--------|------|-------|-----|
| GET | `/audit-logs` | P01 | REQ-API-010 |
| GET | `/logs/access` | P01 | REQ-OBS-002 |
| GET | `/security-events` | P05 | REQ-OBS-003 |
| POST | `/backup` | P06 | REQ-API-014 |
| POST | `/restore` | P06 | REQ-API-014 |

## RBAC matrisi (özet)

| Kaynak | Viewer | Operator | Admin |
|--------|--------|----------|-------|
| hosts okuma | ✓ | ✓ | ✓ |
| hosts yazma | | ✓ | ✓ |
| config apply | | ✓ | ✓ |
| certificates | | ✓ | ✓ |
| waf/ids yazma | | ✓ | ✓ |
| users | | | ✓ |
| backup/restore | | | ✓ |
| bootstrap | özel tek sefer | | |

## Hata kodları (örnek)

| code | HTTP | Anlam |
|------|------|-------|
| `unauthorized` | 401 | Oturum yok/geçersiz |
| `forbidden` | 403 | RBAC |
| `validation_failed` | 400 | Girdi |
| `config_invalid` | 422 | nginx -t fail |
| `reload_failed` | 409/500 | Rollback uygulandı |
| `conflict` | 409 | Versiyon çakışması |
| `rate_limited` | 429 | API koruması |

## Uygulama notları

- OpenAPI CI’da source of truth olacak; bu markdown saparsa OpenAPI kazanır (güncelleme zorunlu).
- P01 bitmeden P02+ endpoint’leri stub olarak “tamamlandı” sayılmaz.
- **P03 LB:** Host’a `upstream_id` bağlanınca tekil `upstream_host` yerine pool render edilir. Aktif health (REQ-LB-008) Plus `health_check` değildir — API worker probe eder, üyeyi `down` işaretler ve throttled apply yapar. Drain → nginx `down`. Metadata/localhost hedefler reddedilir.
- **P04 WAF:** Varsayılan global politika `DetectionOnly`. Blocking = `engine-On.conf`. Exception’lar auditlenir; olay payload’ları maskelenir. Plus `health_check` yok; ModSec audit JSON → `security_events`.
- **P05 IDS:** Bouncer = kontrol düzlemi nginx deny sync (Lua/firewall yok). LAPI host’a publish edilmez. Fail-closed varsayılan. Birleşik olaylar: `GET /security-events?source=waf|crowdsec`.
