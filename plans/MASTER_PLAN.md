# MASTER_PLAN.md — Nginx Security Platform

**Aktif Aşama:** `PHASE_06_PRODUCTION` (**GATE_PASSED** — QA-010 sign-off bekliyor)  
**Versiyon:** 1.8.0  
**Tarih:** 2026-10-22  
**Kapsam kaynağı:** `docs/REQUIREMENTS.md` (148 REQ)

## 1. Ürün hedefi

Self-hosted **Nginx Reverse Proxy + Load Balancer + Web Security Platform**: domain/proxy yönetimi, SSL yaşam döngüsü, LB, ModSecurity/CRS WAF, CrowdSec IDS/IPS, rate limiting, Go API, React (TR/EN) panel, PostgreSQL/(Redis), RBAC, güvenli config pipeline, Docker Compose işletimi, gözlemlenebilirlik ve yedekleme.

## 2. Aşama haritası

```
P01 MVP ──► P02 SSL ──► P03 LB ──► P04 WAF ──► P05 IDS/IPS ──► P06 Production
   │            │          │          │            │               │
   └─ temel     └─ ACME    └─ pools   └─ ModSec    └─ CrowdSec     └─ sertleştirme
      proxy+cfg    certs      health     CRS          bouncer         backup/E2E
```

| Aşama | Dosya | Çıkış kapısı (özet) |
|-------|-------|---------------------|
| P01 | `PHASE_01_MVP.md` | Host CRUD, conf validate/apply/rollback, auth+RBAC temel, UI TR/EN, compose healthy |
| P02 | `PHASE_02_SSL.md` | HTTP-01/DNS-01, Cloudflare, manuel/self-signed/private CA, yenileme |
| P03 | `PHASE_03_LOAD_BALANCER.md` | Pool + 5 algoritma + health/failover/timeout |
| P04 | `PHASE_04_WAF.md` | ModSec+CRS, Detection/Blocking, exceptions, events |
| P05 | `PHASE_05_IDS_IPS.md` | CrowdSec+bouncer, auto/manual ban, allow/deny |
| P06 | `PHASE_06_PRODUCTION.md` | RBAC sert, metrics, backup/restore, upgrade, E2E sign-off |

## 3. Bağımlılık kuralları

- P02, P01 config pipeline (`REQ-CFG-*`) olmadan başlamaz.
- P03, P01 host modeline bağlanır; SSL opsiyonel ama HTTPS upstream P03’te.
- P04 özel nginx imajı gerektirir; P01’de düz nginx ile başlanabilir, P04’te imaj değişimi planlı migration.
- P05 log acquisition için P01 access log yollarına ihtiyaç duyar.
- P06 tüm kritik P01–P05 `VERIFIED` olmadan production checklist imzalanmaz.

## 4. Teknik riskler (gizlenmez)

| ID | Risk | Etki | Azaltma | Aşama |
|----|------|------|---------|-------|
| RISK-01 | ModSecurity connector ↔ nginx sürüm uyumsuzluğu | WAF imajı build kırılır | Pin + CI image smoke | P04 |
| RISK-02 | Nginx OSS’ta aktif health check yok | LB beklentisi karşılanmaz | Passive + control-plane probe; dokümante | P03 |
| RISK-03 | Reload için Docker socket tuzağı | Kritik güvenlik açığı | Config agent; socket yasak | P01 |
| RISK-04 | ACME HTTP-01 conf yarışı | Sertifika fail / trafik kesici | Staging+rollback; challenge window | P02 |
| RISK-05 | DNS-01 Cloudflare token sızıntısı | Domain hijack | Secret store; scope min; leak test | P02 |
| RISK-06 | CRS false-positive | İş kırılması | Default DetectionOnly; exception UX | P04 |
| RISK-07 | CrowdSec bouncer fail-open/closed | Ya kesinti ya korumasızlık | P05’te politika seçimi + test | P05 |
| RISK-08 | Config injection (raw nginx) | RCE/proxy abuse | UI raw kapalı; FS’de yalnızca named allowlist includes + nginx -t/rollback (REQ-PROXY-021) | P01/P06 |
| RISK-09 | Upstream open proxy | SSRF/abuse | Allowlist scheme/host validation | P01/P03 |
| RISK-10 | Secret’ların loglanması | Compliance ihlali | Redaction middleware + test | P01+ |
| RISK-11 | Çok bileşenli compose karmaşıklığı | Operasyonel hata | Aşamalı servis ekleme; healthchecks | ALL |
| RISK-12 | Wildcard + HTTP-01 imkânsız | Kullanıcı karışıklığı | UI’da DNS-01 zorunluluğu | P02 |
| RISK-13 | Host bind `data/logs` + `data/nginx` izinleri (root yazımı) | Host kullanıcı düzenleyemez | Entrypoint `a+rwX`; dokümante | P01/OPS |
| RISK-14 | CrowdSec scenario override yanlış eşik | False positive ban / kaçan tarama | Allowlist alanlar + Validate; serbest YAML yok (REQ-IDS-017) | P05 |
| RISK-15 | CrowdSec LAPI machine credentials desync / CAPI 403 | Engine restart loop | Volume reset + `DISABLE_ONLINE_API=true` (lab) | P05 |
| RISK-16 | Boot-time HUP before CrowdSec signal handlers | exit 2 restart loop; agent unreachable | Entrypoint: copy overrides without HUP; agent `kill -HUP 1` only after stable | P05 |

## 5. Tanım: “bitti” (Definition of Done)

Bir gereksinim yalnızca şu durumda `VERIFIED` olur:

1. Kod production path’te (mock değil).
2. Kabul kriteri karşılanmış.
3. Bağlı otomatik test yeşil **veya** kayıtlı manuel test kanıtı.
4. İlgili `PHASE_*.md` güncellenmiş.
5. Güvenlik kuralları ihlal edilmemiş.

## 6. Çalışma disiplini

Her ajan oturumu: `AGENTS.md` zorunlulukları.  
Kodlamaya geçiş: **kullanıcı onayı sonrası** ve yalnızca aktif aşama.

## 7. İzlenebilirlik

- Tüm 146 REQ → en az bir PHASE dosyasında sahiplenilir (`REQ-QA-009`).
- Bu MASTER_PLAN aşama kapılarını; PHASE dosyaları görev kırılımını tutar.
- PHASE dosyalarında sahiplik listeleri **ellipsis kullanmadan** tek tek REQ ID içerir.

## 8. Onay kapısı

**Durum:** P01 MVP kapısı **yeniden doğrulandı** (2026-10-22): compose healthy, gerçek proxy trafik, invalid conf preserve, `p01-gate.sh` + Playwright yeşil.  
**Sonraki kapı:** Kullanıcı isterse P02+; bu oturumda diğer aşamalara geçilmedi.  
**P01 mimari kilitleri:**
1. Oturum: **HttpOnly cookie + CSRF** (JWT değil)
2. Config agent: **ayrı binary**, shared volume; Docker socket yok
3. Raw nginx snippet: **kapalı**
4. Redis: P01’de **zorunlu** (session store)

## 9. Değişiklik günlüğü

| Tarih | Not |
|-------|-----|
| 2026-10-22 | İlk master plan + 6 aşama + 146 REQ kataloğu |
| 2026-10-22 | Kullanıcı onayı; P01 IN_PROGRESS; oturum/cookie+CSRF, config-agent, Redis zorunlu kilitlendi |
| 2026-10-22 | P01 çekirdek implementasyon + compose smoke; E2E/CI/chaos kapıları açık |
| 2026-10-22 | P01 GATE PASSED: negatif nginx -t, chaos rollback, viewer 403, Playwright, OpenAPI CI |
| 2026-10-22 | P02 SSL: cert CRUD, TLS render, ACME client, CF/mock DNS, UI; lab gate passed |
| 2026-10-22 | P03 LB GATE_PASSED; kullanıcı onayı → P04 WAF IN_PROGRESS |
| 2026-10-22 | P04 WAF GATE_PASSED: ModSec+CRS pin, Detection/Blocking, exceptions, events UI |
| 2026-10-22 | P05 IDS IN_PROGRESS; bouncer=control-plane nginx deny sync |
| 2026-10-22 | P05 IDS GATE_PASSED: CrowdSec+acquis, ban/allow/deny, unified events |
| 2026-10-22 | P01 yeniden doğrulama: http-echo trafik, invalid conf preserve, E2E/gate PASS |
| 2026-10-22 | IDS/rate genişletme: ban history, protected CIDR, rate CRUD, method/endpoint limit, trusted-proxy gate |
| 2026-10-22 | SSL genişletme: zincir/SAN, atomik yazım+rollback, ACME ops, unused list, auto-renew worker, cipher suite, UI uyarıları |
| 2026-10-23 | REQ-IDS-017: CrowdSec tespit eşikleri UI + crowdsec-agent (scenario/profile allowlist apply) |
| 2026-10-23 | REQ-RATE-010: User-Agent allowlist (bad-bot kuralı skipAfter) + WAF UI |
| 2026-10-23 | REQ-WAF-017/018: ModSec global settings + validated custom rules (global/host) |
| 2026-10-23 | REQ-PROXY-021: NPM named custom includes (`data/nginx/custom/`, allowlist, no UI) |
| 2026-10-23 | REQ-OPS-002: host TLS bind `data/certs` (api+nginx; compat `/var/lib/nsp/certs`) |
| 2026-10-23 | REQ-IDS-019: IDS enforcement active/passive (panel toggle; passive skips nginx deny) |
| 2026-10-23 | REQ-WAF-007/UI-007: WAF sekmeli UI + CRS katalog listesi aktif/pasif (SecRuleRemoveById) |
| 2026-10-23 | REQ-PROXY-022: varsayılan 403/404/429/5xx HTML error pages (`data/nginx/error_pages/`) |
| 2026-10-23 | REQ-LB-008: elle disable (`admin_disabled`) health probe ile geri açılmaz |
