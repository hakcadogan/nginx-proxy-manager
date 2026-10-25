# ARCHITECTURE.md — Nginx Security Platform

**Versiyon:** 1.0.0  
**Durum:** Planlama  
**İlgili:** `docs/REQUIREMENTS.md`, `docs/SECURITY.md`

## 1. Hedef mimari özeti

Self-hosted platform; **kontrol düzlemi** (API + UI + DB) ile **veri düzlemi** (Nginx + WAF + bouncer) ayrılır. Operatör paneli üzerinden proxy, SSL, LB, WAF ve IDS politikaları yönetilir; nginx konfigürasyonu bildirimsel modelden üretilir, doğrulanır, sürümlenir ve güvenli reload/rollback ile uygulanır.

```
                    ┌─────────────────────────────────────┐
                    │           Yönetim ağı                │
                    │  ┌─────────┐      ┌──────────────┐  │
 Operatör ─────────►│  │ UI SPA  │─────►│  Go API      │  │
                    │  └─────────┘      │  (control)   │  │
                    │                   └──────┬───────┘  │
                    │                          │          │
                    │              ┌───────────┼────────┐ │
                    │              ▼           ▼        ▼ │
                    │         PostgreSQL     Redis   Config│
                    │                              Agent* │
                    └─────────────────────────────────────┘
                                               │
                         sınırlı IPC / volume / API
                                               ▼
                    ┌─────────────────────────────────────┐
                    │           Veri düzlemi               │
 İnternet ─────────►│  Nginx (+ ModSecurity)              │
                    │       │                             │
                    │       ├── CrowdSec bouncer          │
                    │       ├── access/error logs ──► CrowdSec engine
                    │       └── upstream pools ──► Backends
                    └─────────────────────────────────────┘
```

\*Config Agent: Docker socket **yok**; yalnızca conf yazma + `nginx -t` + reload sinyali (veya eşdeğer kontrollü mekanizma).

## 2. Bileşenler

| Bileşen | Teknoloji | Düzlem | Görev |
|---------|-----------|--------|-------|
| `web` | React + TypeScript | Kontrol | Yönetim paneli, i18n TR/EN |
| `api` | Go | Kontrol | REST API, RBAC, orchestration |
| `db` | PostgreSQL | Kontrol | Durum, audit, config sürümleri |
| `redis` | Redis (opsiyonel) | Kontrol | Session/cache/rate |
| `nginx` | Nginx OSS + ModSecurity v3 connector | Veri | Reverse proxy, LB, TLS terminate, WAF |
| `crowdsec` | CrowdSec | Veri/yan | IDS, karar üretimi |
| `bouncer` | CrowdSec bouncer | Veri | IP engelleme uygulama |
| `acme` | ACME istemcisi (API içi veya sidecar) | Kontrol | Sertifika yaşam döngüsü |
| `config-agent` | Küçük Go helper (tercihen) | Köprü | Validate/reload; least privilege |

## 3. Kontrol vs veri düzlemi

| Kural | Açıklama |
|-------|----------|
| Ayrı container’lar | UI/API/DB ≠ Nginx traffic path |
| Ayrı ağlar | `frontend`, `control`, `data`, `persist` (isimler örnek) |
| Yetki sınırları | API, nginx process’ini root shell ile yönetmez |
| Secret ayrımı | TLS key’ler data volume; API secret’ları control secret |
| Başarısızlık izolasyonu | API down olsa bile mevcut nginx conf trafiği sürdürür |

## 4. Konfigürasyon yaşam döngüsü

```
Desired State (DB)
       │
       ▼
  Template Render (CFG) ──► Staging conf
       │
       ▼
  nginx -t (validate)
       │
  ┌────┴────┐
 fail      ok
  │         │
  ▼         ▼
 reject   Atomic publish
            │
            ▼
         Reload
         ┌──┴──┐
       fail   ok
         │     │
         ▼     ▼
      Rollback  Version++
      (last-good)
```

- Her başarılı apply → `REQ-CFG-004` sürüm kaydı + audit.
- Golden-file / snapshot testleri render determinizmini korur (`REQ-CFG-001`).

## 5. Load balancing (Nginx OSS gerçekleri)

| Algoritma / özellik | OSS desteği | Platform yaklaşımı |
|---------------------|-------------|-------------------|
| Round Robin | Evet (default) | `round_robin` |
| Weighted RR | Evet (`weight=`) | `weighted_round_robin` |
| Least Connections | Evet (`least_conn`) | `least_conn` |
| IP Hash | Evet (`ip_hash`) | weight/backup yok sayılır |
| Generic hash / consistent | Evet | `hash` / `hash_consistent` |
| Pasif health | Evet | `max_fails` / `fail_timeout` |
| Aktif health check | **Hayır (Plus `health_check`)** | Kontrol düzlemi HTTP probe → `down` + reload |
| Sticky cookie | Hayır (Plus) | Kapsam dışı |
| Dinamik upstream API | Hayır (Plus) | Conf regenerate + reload |
| Retry | Evet | Yapılandırılabilir `proxy_next_upstream` (+ tries/timeout); `non_idempotent` uyarı |
| İstek/hata sayaçları | stub_status / exporter | Panel: üye up/down gauge; sayaç exporter opsiyonel |

Upstream değişiklikleri conf regenerate + reload gerektirir.

## 6. SSL / ACME yaşam döngüsü

1. Issue talebi (HTTP-01 veya DNS-01).
2. HTTP-01: challenge location staging conf → validate → reload.
3. DNS-01: Cloudflare API ile TXT; token secret store’da.
4. Sertifika kaydı + host bağlama → TLS conf render → validate → reload.
5. Yenileme job: expiry eşiği (ör. 30 gün); başarısızlıkta mevcut cert korunur.
6. Private key asla audit/app log’a yazılmaz.

## 7. WAF mimarisi

- Nginx imajı: ModSecurity v3 + `ngx_http_modsecurity_module` (sürüm pin).
- OWASP CRS: dosya volume’da; paranoia ve exclusions DB’den üretilen overlay conf.
- Modlar: `DetectionOnly` vs `On` (blocking).
- Audit log → parser → `security_events` (maskeleme ile).
- IP allowlist (`data`/settings → `modsec/ip-allowlist.txt`): `REMOTE_ADDR` eşleşince `ctl:ruleEngine=Off` (CRS bypass; IDS deny ayrı).

**Risk:** Connector/nginx ABI uyumsuzluğu imaj build’ini kırabilir; CI’da imaj smoke zorunlu.

## 8. CrowdSec mimarisi

- Engine: nginx access log acquisition.
- Bouncer: nginx Lua/module **veya** firewall bouncer (host/netns). Seçim `PHASE_05`’te netleştirilir; ikisi birden varsayılan değildir.
- LAPI yalnızca bouncer + API (okuma/karar) erişimine açık.
- Allow/deny listeleri hem CrowdSec hem (gerekirse) nginx `allow`/`deny` ile tutarlı tutulur.

## 9. Veri modeli (yüksek seviye)

- `users`, `roles`, `permissions`, `sessions`
- `proxy_hosts`, `locations`, `upstreams`, `upstream_members`
- `certificates`, `certificate_bindings`
- `waf_policies`, `waf_exceptions`, `security_events`
- `ip_policies` (allow/deny/ban)
- `config_versions`, `audit_logs`
- `settings` (ACME, Cloudflare ref, feature flags)

## 10. Gözlemlenebilirlik

- API: structured JSON log + request_id.
- Nginx: access/error; isteğe bağlı JSON log format.
- Metrics: API `/metrics` + nginx exporter (P06).
- Security events: WAF + CrowdSec birleşik sorgu API’si.

## 11. Dağıtım topolojisi (Compose)

Örnek servisler: `web`, `api`, `db`, `redis`, `nginx`, `crowdsec`, `bouncer` (ve gerekirse `config-agent`).

Volume’lar: `pgdata`, `redisdata`, `nginx_conf_state` (staging/ACME account), `modsec-rules`, `crowdsec-data`.

Host bind-mounts (NPM tarzı, repo kökü `data/`):

| Yol | İçerik |
|-----|--------|
| `data/logs/nginx/` | error, fallback_*, modsec_audit, `proxy_host/*.log`, `proxy_host_error/` |
| `data/logs/api/` | API JSON logları (opsiyonel) |
| `data/logs/crowdsec/` | CrowdSec log |
| `data/nginx/proxy_host/` | Üretilmiş host conf (`*.conf`) |
| `data/nginx/custom/` | NPM named includes (`root_top.conf`, `http.conf`, `server_proxy.conf`, …); allowlist; UI yok |
| `data/certs/<id>/` | Host TLS `fullchain.pem` + `privkey.pem` (`REQ-OPS-002`, `REQ-SSL-013`) |

## 12. Teknik uyumsuzluklar ve kararlar

| Konu | Gerçek | Platform kararı |
|------|--------|-----------------|
| Nginx Plus health_check | OSS’ta yok | Passive + kontrol düzlemi aktif probe |
| ModSecurity resmi nginx | Yok | Custom image + pin |
| Dynamic upstream OSS | Sınırlı | Reload tabanlı |
| CrowdSec nginx bouncer | Ek bağımlılık | P05’te tek bouncer tipi seç |
| ACME HTTP-01 | Geçici conf | Staging + rollback zorunlu |
| Docker socket | Tehlikeli | Yasak (`REQ-CFG-010`, `SECURITY.md`) |

## 13. Gelecek (kapsam dışı şimdilik)

- Kubernetes Operator
- Multi-node HA control plane
- GeoDNS / anycast
