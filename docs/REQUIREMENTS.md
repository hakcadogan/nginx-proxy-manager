# REQUIREMENTS.md — Nginx Security Platform

**Versiyon:** 1.0.0  
**Durum:** Planlama (kod yok)  
**Son güncelleme:** 2026-10-22  
**Toplam gereksinim:** 148

Bu belge proje kapsamının **tek kaynağıdır**. Her gereksinimin benzersiz ID’si, aşaması, modülü, bağımlılığı, kabul kriteri ve doğrulama testi vardır. Hiçbir gereksinim plansız bırakılmaz.

## Durum efsanesi

`PLANNED` | `IN_PROGRESS` | `IMPLEMENTED` | `VERIFIED` | `BLOCKED` | `DEFERRED`

## Aşama efsanesi

| Kod | Dosya | Ad |
|-----|-------|-----|
| P01 | `plans/PHASE_01_MVP.md` | MVP |
| P02 | `plans/PHASE_02_SSL.md` | SSL |
| P03 | `plans/PHASE_03_LOAD_BALANCER.md` | Load Balancer |
| P04 | `plans/PHASE_04_WAF.md` | WAF |
| P05 | `plans/PHASE_05_IDS_IPS.md` | IDS/IPS |
| P06 | `plans/PHASE_06_PRODUCTION.md` | Production |

## Modül efsanesi

| Kod | Açıklama |
|-----|----------|
| `proxy` | Domain / reverse proxy |
| `lb` | Load balancer |
| `ssl` | Sertifika / ACME |
| `waf` | ModSecurity / CRS |
| `ids` | CrowdSec |
| `rate` | Rate / connection / bot |
| `api` | Go REST API |
| `ui` | React yönetim paneli |
| `data` | PostgreSQL / Redis |
| `auth` | RBAC / oturum |
| `cfg` | Config üretimi / reload |
| `ops` | Docker / deploy |
| `obs` | Metrik / log / yedek |
| `qa` | Test / OpenAPI / dokümantasyon |

---

## 1. Reverse Proxy ve Domain Yönetimi

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-PROXY-001 | Proxy host oluşturma (domain, upstream, path) | P01 | proxy | REQ-API-001, REQ-DATA-001 | VERIFIED | Host DB’de ve panoda listelenir | API + UI E2E: create host |
| REQ-PROXY-002 | Proxy host okuma / listeleme / filtreleme | P01 | proxy | REQ-PROXY-001 | VERIFIED | Sayfalı liste, domain araması | Unit + API test |
| REQ-PROXY-003 | Proxy host güncelleme | P01 | proxy | REQ-PROXY-001, REQ-CFG-001 | VERIFIED | Değişiklik config üretimi tetikler | Integration: update → render |
| REQ-PROXY-004 | Proxy host silme (soft/hard politika) | P01 | proxy | REQ-PROXY-001, REQ-CFG-003 | VERIFIED | Silinen host nginx’ten kalkar | Integration: delete → reload |
| REQ-PROXY-005 | HTTP → HTTPS yönlendirme seçeneği | P01 | proxy | REQ-PROXY-001 | VERIFIED | 301/302 yapılandırılabilir | Config snapshot test |
| REQ-PROXY-006 | Custom location / path routing | P01 | proxy | REQ-PROXY-001 | VERIFIED | Path başına upstream | Config + E2E proxy |
| REQ-PROXY-007 | WebSocket / Upgrade desteği | P01 | proxy | REQ-PROXY-001 | VERIFIED | Upgrade header’ları doğru | E2E WebSocket |
| REQ-PROXY-008 | Custom header ekleme/çıkarma | P01 | proxy | REQ-PROXY-001 | VERIFIED | Header kuralları config’te | Config unit test |
| REQ-PROXY-009 | Access/error log per-host aç/kapa + format preset | P01 | proxy | REQ-OBS-002 | VERIFIED | Access `proxy_host/`; error `proxy_host_error/` + global `error.log`; format main/combined/detailed/json | Config unit + apply smoke |
| REQ-PROXY-010 | Host enable/disable (trafik kesme) | P01 | proxy | REQ-CFG-002 | VERIFIED | Disabled host 503 veya config dışı | Integration |
| REQ-PROXY-011 | Çoklu domain / alias (server_name) | P01 | proxy | REQ-PROXY-001 | VERIFIED | Alias’lar server_name’de | Config unit |
| REQ-PROXY-012 | Upstream scheme (http/https) ve SNI | P03 | proxy | REQ-LB-001 | VERIFIED | HTTPS upstream + SNI | Integration |
| REQ-PROXY-013 | HSTS / güvenlik header preset’leri | P06 | proxy | REQ-PROXY-001 | VERIFIED | Preset uygulanır | Config + header E2E |
| REQ-PROXY-014 | HTTP/HTTPS dinleme seçenekleri (listen 80/443) | P06 | proxy | REQ-PROXY-001 | VERIFIED | Host bazlı listen_http / listen_https | Config unit + apply smoke |
| REQ-PROXY-015 | HTTP/2 dinleme (ssl http2) | P06 | proxy | REQ-PROXY-014, REQ-SSL-001 | VERIFIED | TLS server’da http2 aç/kapa | Config unit |
| REQ-PROXY-016 | İstek gövde boyutu limiti (client_max_body_size) | P06 | proxy | REQ-PROXY-001 | VERIFIED | Host bazlı size (örn. 10m) | Config unit + apply smoke |
| REQ-PROXY-017 | Host bazlı connect/send/read timeout (doğrudan upstream) | P06 | proxy | REQ-PROXY-001 | VERIFIED | Timeout’lar conf’te; pool’da LB timeout | Config unit + apply smoke |
| REQ-PROXY-018 | gRPC proxy (grpc_pass) | P06 | proxy | REQ-PROXY-001 | VERIFIED | proxy_protocol=grpc → grpc_pass | Config unit |
| REQ-PROXY-019 | Güvenilir proxy listesi + real_ip (gerçek istemci IP) | P06 | proxy | REQ-CFG-001 | VERIFIED | set_real_ip_from + real_ip_header | Config unit + settings API smoke |
| REQ-PROXY-020 | Proxy host upstream bağlantı testi (TCP probe) | P06 | proxy | REQ-PROXY-001 | VERIFIED | POST /hosts/{id}/probe | API smoke |
| REQ-PROXY-021 | NPM tarzı named custom includes (`data/nginx/custom/`) | P06 | proxy | REQ-CFG-008, REQ-CFG-002 | VERIFIED | Allowlist dosya adları; UI editör yok; `nginx -t` + rollback | Config unit |
| REQ-PROXY-022 | Varsayılan HTML hata sayfaları (403/404/429/5xx) | P06 | proxy | REQ-CFG-001 | IMPLEMENTED | `error_page` + `data/nginx/error_pages/`; upstream için `proxy_intercept_errors` | Config unit + apply smoke |

---

## 2. Load Balancing

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-LB-001 | Backend pool CRUD | P03 | lb | REQ-PROXY-001, REQ-DATA-001 | VERIFIED | Pool/üyeler; opsiyonel `max_conns`; üye düzenleme | API CRUD + config unit |
| REQ-LB-002 | Round Robin algoritması | P03 | lb | REQ-LB-001 | VERIFIED | Eşit dağılım (OSS default) | Traffic distribution test |
| REQ-LB-003 | Weighted Round Robin | P03 | lb | REQ-LB-001 | VERIFIED | `weight=` parametresi | Config + traffic test |
| REQ-LB-004 | Least Connections | P03 | lb | REQ-LB-001 | VERIFIED | `least_conn` directive | Config unit + load test |
| REQ-LB-005 | IP Hash | P03 | lb | REQ-LB-001 | VERIFIED | `ip_hash` sticky | Affinity E2E |
| REQ-LB-006 | Hash tabanlı LB (hash / consistent) | P03 | lb | REQ-LB-001 | VERIFIED | `hash $key [consistent]` | Config + affinity test |
| REQ-LB-007 | Passive health check (max_fails/fail_timeout) | P03 | lb | REQ-LB-001 | VERIFIED | Unhealthy backend çıkarılır | Failover integration |
| REQ-LB-008 | Aktif health check (uyumluluk yolu) | P03 | lb | REQ-LB-001 | IMPLEMENTED | OSS harici probe; elle `admin_disabled` üyeyi probe tekrar açmaz | Health probe + disable smoke |
| REQ-LB-009 | Failover / backup sunucu | P03 | lb | REQ-LB-007 | VERIFIED | `backup` flag çalışır | Failover E2E |
| REQ-LB-010 | Connect / send / read timeout | P03 | lb | REQ-LB-001 | VERIFIED | Timeout’lar config’te | Config unit |
| REQ-LB-011 | Backend drain / bakım modu | P03 | lb | REQ-LB-001 | VERIFIED | Drain edilen üye yeni bağlantı almaz | Integration |
| REQ-LB-012 | Pool metrikleri (aktif bağlantı, hata) | P06 | lb | REQ-OBS-001 | VERIFIED | Üye up/down gauge + health API; istek/hata sayacı stub_status/exporter ile (OSS sınır) | Metrics scrape + health API |
| REQ-LB-013 | Upstream retry politikası (`proxy_next_upstream`) + non-idempotent uyarısı | P06 | lb | REQ-LB-010 | VERIFIED | Pool’da koşullar/tries/timeout; UI’da `non_idempotent` risk uyarısı | Config unit + apply smoke |

**Teknik not (LB):** Nginx Open Source’ta aktif health check (nginx Plus `health_check`) **yoktur**. REQ-LB-008 için kontrol düzlemi HTTP probe + `down` + reload kullanılır; Plus varsayılmaz. Sticky cookie / dinamik upstream API de OSS’ta yok. İstek ve hata sayıları native upstream API olmadan panelde gösterilmez — alternatif: `stub_status` veya Prometheus nginx exporter (kapsam dışı / opsiyonel).

---

## 3. SSL / TLS ve Sertifikalar

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-SSL-001 | Manuel sertifika yükleme (cert+key) | P02 | ssl | REQ-PROXY-001 | VERIFIED | PEM doğrulanır, host’a bağlanır | Upload + TLS handshake |
| REQ-SSL-002 | Self-signed sertifika üretimi | P02 | ssl | REQ-SSL-001 | VERIFIED | Geçerli self-signed oluşur | openssl verify test |
| REQ-SSL-003 | Private CA ile imzalama | P02 | ssl | REQ-SSL-001 | VERIFIED | CA zinciri doğrulanır | Chain validation test |
| REQ-SSL-004 | Let's Encrypt HTTP-01 | P02 | ssl | REQ-SSL-010, REQ-CFG-002 | IMPLEMENTED | Sertifika alınır ve yenilenir | ACME staging E2E |
| REQ-SSL-005 | Let's Encrypt DNS-01 | P02 | ssl | REQ-SSL-006 | IMPLEMENTED | DNS challenge tamamlanır | ACME DNS staging |
| REQ-SSL-006 | Cloudflare DNS API entegrasyonu | P02 | ssl | REQ-OPS-005 | VERIFIED | TXT kaydı create/delete | Cloudflare mock/integration |
| REQ-SSL-007 | Wildcard sertifika (DNS-01) | P02 | ssl | REQ-SSL-005 | VERIFIED | `*.domain` alınır | Wildcard TLS test |
| REQ-SSL-008 | Otomatik yenileme (expiry eşiği) | P02 | ssl | REQ-SSL-004 | VERIFIED | Süresi dolmadan yenilenir | Renewal job unit |
| REQ-SSL-009 | Sertifika envanteri ve expiry uyarıları | P02 | ssl | REQ-OBS-003 | VERIFIED | Panelde gün/uyarı | UI + API test |
| REQ-SSL-010 | ACME hesap ve EAB desteği (opsiyonel) | P02 | ssl | REQ-DATA-001 | IMPLEMENTED | Hesap kaydı güvenli saklanır | Unit |
| REQ-SSL-011 | Challenge sırasında güvenli reload | P02 | ssl | REQ-CFG-003 | VERIFIED | Challenge path yayınlanır, rollback güvenli | Integration |
| REQ-SSL-012 | TLS versiyon / cipher politikası | P02 | ssl | REQ-CFG-001 | VERIFIED | Min TLS 1.2 varsayılan | Config + sslscan |
| REQ-SSL-013 | Sertifika private key secret yönetimi | P02 | ssl | REQ-OPS-005 | VERIFIED | Key volume/secret’ta, log yok | Secret leak test |
| REQ-SSL-014 | OCSP stapling (destekleniyorsa) | P06 | ssl | REQ-SSL-004 | VERIFIED | Stapling config’te | Config unit |
| REQ-SSL-015 | Zincir + SAN/domain doğrulama | P02 | ssl | REQ-SSL-001 | VERIFIED | Zincir imza + bind SAN eşleşmesi | Unit + bind API |
| REQ-SSL-016 | Sertifika atomik yazım + geri alma | P02 | ssl | REQ-SSL-013 | VERIFIED | Temp+rename; `.prev` rollback | Unit |
| REQ-SSL-017 | ACME işlem geçmişi / hata logları | P02 | ssl | REQ-SSL-004 | VERIFIED | issue/renew/rollback kaydı | API |
| REQ-SSL-018 | Kullanılmayan sertifika listesi | P02 | ssl | REQ-SSL-009 | VERIFIED | `?unused=1` | API smoke |
| REQ-SSL-019 | Self-signed güven uyarısı (UI) | P02 | ssl | REQ-SSL-002 | VERIFIED | Panelde açık uyarı + API trust_warning | Smoke |

**Teknik not (ACME):** HTTP-01 için `.well-known/acme-challenge/` konumu challenge süresince yayınlanmalı; DNS-01 Cloudflare token’ı secret store’da tutulmalı. Yenileme başarısızlığında eski sertifika korunur.

---

## 4. WAF (ModSecurity v3 + OWASP CRS)

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-WAF-001 | ModSecurity v3 + nginx connector imajı | P04 | waf | REQ-OPS-001 | VERIFIED | Data plane ModSec ile ayağa kalkar | Container health + `modsecurity_rules` |
| REQ-WAF-002 | OWASP CRS kurulumu ve sürüm pinleme | P04 | waf | REQ-WAF-001 | VERIFIED | CRS kuralları yüklenir | Rule load test |
| REQ-WAF-003 | Detection Only modu | P04 | waf | REQ-WAF-002 | VERIFIED | İstek engellenmez, loglanır | Attack → 200 + alert |
| REQ-WAF-004 | Blocking modu | P04 | waf | REQ-WAF-002 | VERIFIED | Saldırı 403/blocked | Attack → block E2E |
| REQ-WAF-005 | Host/global WAF enable | P04 | waf | REQ-WAF-001, REQ-PROXY-001 | VERIFIED | Host bazlı aç/kapa | Config + E2E |
| REQ-WAF-006 | Paranoia level ayarı | P04 | waf | REQ-WAF-002 | VERIFIED | PL 1–4 uygulanır | Config unit |
| REQ-WAF-007 | Kural istisnası (rule ID exclude) + CRS katalog aktif/pasif | P04 | waf | REQ-WAF-002 | IMPLEMENTED | Belirli kural atlanır; katalogda SecRuleRemoveById toggle; PATCH ile düzenleme | Exception E2E + CRS list API |
| REQ-WAF-008 | Path / argüman bazlı istisna | P04 | waf | REQ-WAF-007 | VERIFIED | Scoped exclusion | Integration |
| REQ-WAF-009 | Güvenlik olayları listesi | P04 | waf | REQ-OBS-003, REQ-DATA-001 | VERIFIED | Olaylar panoda | API + UI |
| REQ-WAF-010 | Olay detayı (rule, payload özeti) | P04 | waf | REQ-WAF-009 | VERIFIED | Hassas veri maskeli | Privacy unit |
| REQ-WAF-011 | CRS false-positive tuning iş akışı | P04 | waf | REQ-WAF-007 | VERIFIED | Olaydan istisna önerisi | UI flow E2E |
| REQ-WAF-012 | WAF audit log yapılandırması | P04 | waf | REQ-OBS-002 | VERIFIED | Audit log yolu ve seviye | Config unit |
| REQ-WAF-013 | Anomaly scoring threshold (inbound/outbound) | P06 | waf | REQ-WAF-002 | VERIFIED | Overlay’de tx.*_anomaly_score_threshold | Config unit + apply smoke |
| REQ-WAF-014 | Saldırı türü raporu (CRS rule prefix) | P06 | waf | REQ-WAF-009 | VERIFIED | SQLi/XSS/LFI/protocol agregasyonu | API report smoke |
| REQ-WAF-015 | Blocking geçişinde yönetici onayı + uyarı | P06 | waf | REQ-WAF-004 | VERIFIED | UI confirm + DetectionOnly varsayılan banner | UI |
| REQ-WAF-016 | Global kural istisnasında etki uyarısı | P06 | waf | REQ-WAF-007 | VERIFIED | Host/path/arg boşsa uyarı + confirm | UI |
| REQ-WAF-017 | ModSec global ayarlar (audit/debug/body) | P04 | waf | REQ-WAF-012 | VERIFIED | Allowlist alanlar overlay’e yazılır; ham conf yok | Unit + apply |
| REQ-WAF-018 | Özel ModSec kuralları (global/host) | P04 | waf | REQ-WAF-017, REQ-CFG-008 | VERIFIED | Yalnızca SecRule/SecAction/SecMarker/Remove*; Include yasak | Unit + apply |
| REQ-WAF-019 | WAF IP/CIDR allowlist | P06 | waf | REQ-WAF-001, REQ-PROXY-019 | IMPLEMENTED | Allowlist IP → `ctl:ruleEngine=Off`; IDS deny’den bağımsız | Unit + API + UI |

**Teknik not (WAF):** Resmi `nginx` paketinde ModSecurity yoktur; özel imaj veya `ngx_http_modsecurity_module` gerekir. CRS SQLi/XSS/path/protocol kuralları CRS paketinden gelir (920–944). Aktif body inceleme: `SecRequestBodyAccess On`. CRS sürüm takibi imaj pin + `crs-version.txt`; in-app CRS upgrade yok (imaj rebuild). Anomaly eşiği CRS `tx.inbound_anomaly_score_threshold` ile yönetilir. WAF IP allowlist (`REQ-WAF-019`) ModSecurity’yi atlar; CrowdSec/nginx deny için IDS allowlist (`REQ-IDS-006`) ayrıdır. Gerçek istemci IP için trusted proxies gerekir.

---

## 5. IDS/IPS (CrowdSec)

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-IDS-001 | CrowdSec engine container | P05 | ids | REQ-OPS-001 | VERIFIED | Engine healthy, log okur | Healthcheck |
| REQ-IDS-002 | Nginx log acquisition | P05 | ids | REQ-IDS-001, REQ-OBS-002 | VERIFIED | Access log parse edilir | Acquisition test |
| REQ-IDS-003 | CrowdSec bouncer (nginx veya firewall) | P05 | ids | REQ-IDS-001 | VERIFIED | Kararlar uygulanır | Ban E2E |
| REQ-IDS-004 | Otomatik IP engelleme | P05 | ids | REQ-IDS-003 | VERIFIED | Eşik aşımında ban | Simulation test |
| REQ-IDS-005 | Manuel IP ban | P05 | ids | REQ-IDS-003, REQ-API-001 | VERIFIED | API/UI ile ban | API test |
| REQ-IDS-006 | Allowlist | P05 | ids | REQ-IDS-003 | VERIFIED | Allowlisted IP engellenmez | Allowlist E2E |
| REQ-IDS-007 | Denylist | P05 | ids | REQ-IDS-003 | VERIFIED | Denylist anında blok | Denylist E2E |
| REQ-IDS-008 | Ban süresi / unban | P05 | ids | REQ-IDS-005 | VERIFIED | TTL, tekli/toplu unban (onay + bulk-delete) | API + UI |
| REQ-IDS-009 | Karar / alert görüntüleme | P05 | ids | REQ-IDS-001, REQ-UI-001 | VERIFIED | Panelde karar listesi + IP arama | UI E2E |
| REQ-IDS-010 | Hub koleksiyonları (nginx, http) | P05 | ids | REQ-IDS-001 | VERIFIED | Gerekli scenario’lar yüklü | cscli list test |
| REQ-IDS-011 | Bouncer API key secret yönetimi | P05 | ids | REQ-OPS-005 | VERIFIED | Key secret’ta | Secret test |
| REQ-IDS-012 | Engelleme geçmişi (ban history) | P05 | ids | REQ-IDS-005 | VERIFIED | create/delete/expire/sync kaydı | API history |
| REQ-IDS-013 | Güvenlik olay zaman çizelgesi | P05 | ids | REQ-OBS-003 | VERIFIED | UI timeline (IP, kaynak, tür, zaman) | API smoke |
| REQ-IDS-014 | Korumalı CIDR (yönetim/loopback) | P05 | ids | REQ-IDS-005 | VERIFIED | Ban/deny reddedilir; CrowdSec skip | Unit + API |
| REQ-IDS-015 | Trusted-proxy gerçek IP uyarısı | P05 | ids | REQ-PROXY-014 | VERIFIED | Trusted proxy yoksa uyarı; XFF spoof yok | API smoke |
| REQ-IDS-016 | İsteğe bağlı GeoIP (ülke kodu) | P05 | ids | REQ-IDS-012 | DEFERRED | MMDB bağlanınca country_code | — |
| REQ-IDS-017 | Tespit eşikleri UI (scenario/profile) | P05 | ids | REQ-IDS-004, REQ-IDS-010 | VERIFIED | Panelden capacity/leakspeed/blackhole/ban süresi; serbest YAML yok; agent ile apply+HUP | Unit + API smoke |
| REQ-IDS-018 | CSV/toplu IP politika ekleme | P05 | ids | REQ-IDS-005 | VERIFIED | Ortak gerekçe + IP listesi; max 500; tek apply | API smoke + UI |
| REQ-IDS-019 | IDS engelleme aktif/pasif | P05 | ids | REQ-IDS-003 | VERIFIED | Panelden active/passive; pasifte nginx deny yok | Unit + API |

**Teknik not (CrowdSec):** Bouncer, LAPI kararlarını **kontrol düzlemi sync → nginx `deny`** ile uygular (Lua bouncer yok). Log analizi (CrowdSec) ile aktif engelleme (nginx deny) ayrıdır. `ids_enforcement=passive` (REQ-IDS-019) iken kararlar DB/panelde kalır; conf’a allow/deny yazılmaz. Gerçek istemci IP yalnızca `trusted_proxies` + doğrulanmış header ile; istemci XFF spoof’una güvenilmez. Tespit eşikleri (REQ-IDS-017) allowlist edilmiş senaryo/profile YAML üretir; CrowdSec container içindeki agent Docker socket olmadan dosya yazar ve HUP gönderir.

---

## 6. Rate Limiting, Connection Limiting, Bot Koruması

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-RATE-001 | Request rate limit (limit_req) | P01 | rate | REQ-CFG-001 | VERIFIED | Zone + rate uygulanır | Burst load test |
| REQ-RATE-002 | Connection limit (limit_conn) | P01 | rate | REQ-CFG-001 | VERIFIED | Eşzamanlı bağlantı sınırı | Conn flood test |
| REQ-RATE-003 | Host / location bazlı limit profili | P01 | rate | REQ-RATE-001 | VERIFIED | Profil atanabilir | Config unit |
| REQ-RATE-004 | Bot koruması (User-Agent / bad bot kuralları) | P04 | rate | REQ-WAF-001 | VERIFIED | Bilinen bad bot blok | UA E2E |
| REQ-RATE-005 | Challenge / soft block politikası (temel) | P06 | rate | REQ-RATE-001 | IMPLEMENTED | 429 + profil `retry_after_seconds` → `Retry-After` header | Unit + apply |
| REQ-RATE-006 | Limit ihlal metrikleri | P06 | rate | REQ-OBS-001 | VERIFIED | Metrik artar | Metrics test |
| REQ-RATE-007 | HTTP metot allow/deny + endpoint rate | P01 | rate | REQ-RATE-003 | VERIFIED | Host/location method + profil | Config unit + apply |
| REQ-RATE-008 | IP rate yalnızca trusted proxy ile | P01 | rate | REQ-PROXY-014, REQ-RATE-001 | VERIFIED | Trusted proxy yoksa limit_req yok | Unit test |
| REQ-RATE-009 | Rate profil CRUD API/UI | P01 | rate | REQ-RATE-003 | VERIFIED | Oluştur/güncelle/sil | API smoke |
| REQ-RATE-010 | User-Agent allowlist (iyi bot / izleme) | P04 | rate | REQ-RATE-004 | VERIFIED | Allowlist UA, bad-bot kuralını (1000100) atlar; serbest regex yok | Unit + apply smoke |

**Teknik not (UA allowlist):** Desenler `@pmFromFile` substring eşleşmesi (ModSec). CrowdSec IP ban’ını kaldırmaz — tarayıcı botları için gerekirse IDS allowlist (IP) ayrı kullanılır.

---

## 7. Go REST API

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-API-001 | Go HTTP sunucusu (versioned `/api/v1`) | P01 | api | REQ-DATA-001 | VERIFIED | Health + version endpoint | Smoke test |
| REQ-API-002 | OpenAPI 3 spesifikasyonu | P01 | api | REQ-API-001 | VERIFIED | Spec CI’da doğrulanır | openapi-validator |
| REQ-API-003 | Proxy host endpoints | P01 | api | REQ-PROXY-001 | VERIFIED | CRUD sözleşmesi | Contract test |
| REQ-API-004 | Config apply / validate / rollback endpoints | P01 | api | REQ-CFG-002 | VERIFIED | Uygulama sonucu döner | Integration |
| REQ-API-005 | SSL certificate endpoints | P02 | api | REQ-SSL-001 | VERIFIED | Upload/issue/renew | Contract |
| REQ-API-006 | LB pool endpoints | P03 | api | REQ-LB-001 | VERIFIED | Pool CRUD | Contract |
| REQ-API-007 | WAF policy / events endpoints | P04 | api | REQ-WAF-005 | VERIFIED | Policy + events | Contract |
| REQ-API-008 | CrowdSec / IP policy endpoints | P05 | api | REQ-IDS-005 | VERIFIED | Ban/allow/deny | Contract |
| REQ-API-009 | Auth / session endpoints | P01 | api | REQ-AUTH-001 | VERIFIED | Login/logout/refresh | Auth E2E |
| REQ-API-010 | Audit log query endpoints | P01 | api | REQ-DATA-003 | VERIFIED | Filtreli audit | API test |
| REQ-API-011 | Structured JSON logging | P01 | api | — | VERIFIED | Request ID, no secrets | Log schema test |
| REQ-API-012 | Idempotent write (Idempotency-Key) kritik işlemlerde | P06 | api | REQ-API-004 | VERIFIED | Çift apply güvenli | Idempotency test |
| REQ-API-013 | Rate limit API (kontrol düzlemi) | P06 | api | REQ-AUTH-001 | VERIFIED | Brute-force yavaşlatma | Abuse test |
| REQ-API-014 | Backup / restore endpoints | P06 | api | REQ-OBS-004 | VERIFIED | Yedek al/yükle | Integration |

---

## 8. React + TypeScript Yönetim Paneli

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-UI-001 | React + TS SPA iskeleti | P01 | ui | REQ-API-001 | VERIFIED | Build + route shell | Build CI |
| REQ-UI-002 | Türkçe / İngilizce i18n | P01 | ui | REQ-UI-001 | VERIFIED | Dil değiştirilir, kalıcı | i18n E2E |
| REQ-UI-003 | Proxy host yönetim ekranları | P01 | ui | REQ-API-003 | VERIFIED | CRUD UI | Playwright |
| REQ-UI-004 | Config durum / apply / rollback UI | P01 | ui | REQ-API-004 | VERIFIED | Operatör akışı | E2E |
| REQ-UI-005 | SSL yönetim ekranları | P02 | ui | REQ-API-005 | VERIFIED | Issue/upload/renew | E2E |
| REQ-UI-006 | LB pool ekranları | P03 | ui | REQ-API-006 | VERIFIED | Pool/üyeler | E2E |
| REQ-UI-007 | WAF politika ve olay ekranları | P04 | ui | REQ-API-007 | IMPLEMENTED | Sekmeli UI + CRS kural listesi aktif/pasif | E2E |
| REQ-UI-008 | IDS/IP politika ekranları | P05 | ui | REQ-API-008 | VERIFIED | Ban/allow/deny | E2E |
| REQ-UI-009 | Kullanıcı / rol yönetimi UI | P06 | ui | REQ-AUTH-003 | VERIFIED | RBAC yönetimi | E2E |
| REQ-UI-010 | Dashboard (metrik özeti) | P06 | ui | REQ-OBS-001 | VERIFIED | Temel KPI’lar | UI test |
| REQ-UI-011 | Erişilebilir form validasyonu | P01 | ui | REQ-UI-001 | VERIFIED | Hatalar kullanıcıya | Component test |
| REQ-UI-012 | Oturum timeout / yeniden giriş | P01 | ui | REQ-AUTH-002 | VERIFIED | Expire sonrası login | E2E |

---

## 9. Veri Katmanı (PostgreSQL / Redis)

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-DATA-001 | PostgreSQL şema + migration | P01 | data | REQ-OPS-001 | VERIFIED | Migration ileri/geri | migrate test |
| REQ-DATA-002 | Redis (session / cache / rate — gerektiğinde) | P01 | data | REQ-OPS-001 | VERIFIED | Redis health; opsiyonel kapalı mod | Integration |
| REQ-DATA-003 | Audit log tablosu (kim, ne, ne zaman) | P01 | data | REQ-DATA-001 | VERIFIED | Mutasyonlar auditlenir | Audit unit |
| REQ-DATA-004 | Yapılandırılmış uygulama logları | P01 | data | REQ-API-011 | VERIFIED | JSON alanları standart | Schema test |
| REQ-DATA-005 | Config sürüm kayıtları DB’de | P01 | data | REQ-CFG-004 | VERIFIED | Her apply versiyonlanır | Integration |
| REQ-DATA-006 | Soft-delete / retention politikası | P06 | data | REQ-DATA-001 | VERIFIED | Retention job | Unit |
| REQ-DATA-007 | DB yedekleme uyumu | P06 | data | REQ-OBS-004 | VERIFIED | pg_dump restore | Backup E2E |

---

## 10. RBAC ve Oturum Güvenliği

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-AUTH-001 | Kullanıcı modeli + parola hash (argon2id) | P01 | auth | REQ-DATA-001 | VERIFIED | Hash doğrulanır | Unit |
| REQ-AUTH-002 | Session / JWT güvenli oturum | P01 | auth | REQ-AUTH-001 | VERIFIED | HttpOnly cookie veya secure JWT | Auth E2E |
| REQ-AUTH-003 | RBAC rolleri (Admin, Operator, Viewer) | P01 | auth | REQ-AUTH-001 | VERIFIED | Yetkisiz 403 | Authz test |
| REQ-AUTH-004 | İzin matrisi endpoint bazlı | P01 | auth | REQ-AUTH-003 | VERIFIED | Matris dokümante + enforce | Table-driven test |
| REQ-AUTH-005 | İlk admin bootstrap (güvenli) | P01 | auth | REQ-AUTH-001 | VERIFIED | Tek seferlik kurulum | Bootstrap E2E |
| REQ-AUTH-006 | Parola politikası / kilitlenme | P06 | auth | REQ-AUTH-001 | VERIFIED | Brute-force kilidi | Abuse test |
| REQ-AUTH-007 | MFA (TOTP) opsiyonel | P06 | auth | REQ-AUTH-002 | VERIFIED | MFA enforce edilebilir | MFA E2E |
| REQ-AUTH-008 | API token (scoped) operasyonel otomasyon | P06 | auth | REQ-AUTH-003 | VERIFIED | Scope sınırlı token | Token test |
| REQ-AUTH-009 | CSRF koruması (cookie oturumda) | P01 | auth | REQ-AUTH-002 | VERIFIED | CSRF olmadan mutasyon reddedilir | Security test |

---

## 11. Nginx Konfigürasyon Üretimi, Doğrulama, Sürümleme, Reload, Rollback

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-CFG-001 | Bildirimsel modelden nginx conf üretimi | P01 | cfg | REQ-PROXY-001 | VERIFIED | Deterministik render | Snapshot golden test |
| REQ-CFG-002 | `nginx -t` doğrulama kapısı | P01 | cfg | REQ-CFG-001 | VERIFIED | Geçersiz conf apply edilmez | Negative test |
| REQ-CFG-003 | Güvenli reload (HUP / kontrollü) | P01 | cfg | REQ-CFG-002 | VERIFIED | Reload sonucu raporlanır | Integration |
| REQ-CFG-004 | Config sürümleme | P01 | cfg | REQ-DATA-005 | VERIFIED | Diff + history | API test |
| REQ-CFG-005 | Otomatik rollback (başarısız reload) | P01 | cfg | REQ-CFG-003 | VERIFIED | Son iyi conf geri gelir | Failure injection |
| REQ-CFG-006 | Manuel rollback seçilen sürüme | P01 | cfg | REQ-CFG-004 | VERIFIED | Seçilen sürüm apply | E2E |
| REQ-CFG-007 | Staging dosya → atomic swap | P01 | cfg | REQ-CFG-002 | VERIFIED | Yarım yazım yok | FS integration |
| REQ-CFG-008 | Template güvenlik (injection yok) | P01 | cfg | REQ-CFG-001 | VERIFIED | Kullanıcı girdisi escape | Fuzz / unit |
| REQ-CFG-009 | Dry-run validate endpoint | P01 | cfg | REQ-CFG-002 | VERIFIED | Apply olmadan test | API test |
| REQ-CFG-010 | Config agent (sınırlı yetki) | P01 | cfg | REQ-OPS-003 | VERIFIED | Socket/shell yok; IPC/API | Security review |

**Teknik not (CFG):** Reload için Docker socket **kullanılmaz**. Ayrı, least-privilege config agent veya nginx container içi kontrollü reload endpoint’i kullanılır.

---

## 12. Docker Compose, Volume, Healthcheck, Ağ, Secret

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-OPS-001 | Docker Compose stack | P01 | ops | — | VERIFIED | `compose up` healthy | Smoke |
| REQ-OPS-002 | Kalıcı volume’lar (data, conf, certs, logs) | P01 | ops | REQ-OPS-001 | VERIFIED | Host bind: `data/logs`, `data/nginx`, `data/certs` | Persistence smoke |
| REQ-OPS-003 | Ağ izolasyonu (frontend/backend/data) | P01 | ops | REQ-OPS-001 | VERIFIED | DB dışarı kapalı | Network policy test |
| REQ-OPS-004 | Container healthcheck’ler | P01 | ops | REQ-OPS-001 | VERIFIED | Unhealthy tespit | compose ps |
| REQ-OPS-005 | Secret yönetimi (env/file, not git) | P01 | ops | REQ-OPS-001 | VERIFIED | `.env.example` only | Secret scan CI |
| REQ-OPS-006 | Data plane / control plane ayrımı | P01 | ops | REQ-OPS-003 | VERIFIED | Ayrı servisler | Arch test |
| REQ-OPS-007 | Kaynak limitleri (CPU/mem) | P06 | ops | REQ-OPS-001 | VERIFIED | Limit’ler tanımlı | compose config |
| REQ-OPS-008 | Güncelleme prosedürü (rolling) | P06 | ops | REQ-OPS-001 | VERIFIED | Dokümante + test edilmiş | Upgrade runbook E2E |
| REQ-OPS-009 | Non-root container’lar (mümkün olduğunca) | P06 | ops | REQ-OPS-001 | VERIFIED | Rootless tercih | Image scan |

---

## 13. Metrikler, Loglar, Yedekleme

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-OBS-001 | Metrik endpoint (Prometheus format) | P06 | obs | REQ-API-001 | VERIFIED | Scrape başarılı | Prom tool test |
| REQ-OBS-002 | Erişim logları toplama / görüntüleme | P01 | obs | REQ-PROXY-009 | VERIFIED | Host volume `data/logs/nginx` + `proxy_host/` + `proxy_host_error/` | Persistence smoke |
| REQ-OBS-003 | Güvenlik olayları (WAF/IDS) birleşik görünüm | P05 | obs | REQ-WAF-009, REQ-IDS-009 | VERIFIED | Kaynak etiketli olaylar | API test |
| REQ-OBS-004 | Yedekleme (DB + conf + certs meta) | P06 | obs | REQ-DATA-007 | VERIFIED | Backup artifact üretilir | Backup test |
| REQ-OBS-005 | Geri yükleme | P06 | obs | REQ-OBS-004 | IMPLEMENTED | Settings restore + pg_dump runbook; full host rehydrate manuel | Restore E2E |
| REQ-OBS-006 | Log retention / rotation | P06 | obs | REQ-OBS-002 | VERIFIED | DB retention + dosya rotate (`settings/logs`, `ops/log-rotate`) | Unit + API |
| REQ-OBS-007 | Alert kuralları (expiry, reload fail) | P06 | obs | REQ-OBS-001 | VERIFIED | Alert tetiklenir | Alert test |

---

## 14. Kalite, Test, Dokümantasyon

| ID | Açıklama | Aşama | Modül | Bağımlılık | Durum | Kabul kriteri | Doğrulama testi |
|----|----------|-------|-------|------------|-------|---------------|-----------------|
| REQ-QA-001 | Unit test altyapısı (Go + TS) | P01 | qa | — | VERIFIED | CI green | CI |
| REQ-QA-002 | Integration test altyapısı | P01 | qa | REQ-OPS-001 | VERIFIED | compose test profile | CI |
| REQ-QA-003 | E2E test altyapısı (Playwright vb.) | P01 | qa | REQ-UI-001 | VERIFIED | Kritik akışlar | CI nightly |
| REQ-QA-004 | OpenAPI contract testleri | P01 | qa | REQ-API-002 | VERIFIED | Spec ↔ impl | CI |
| REQ-QA-005 | Kurulum dokümantasyonu | P01 | qa | REQ-OPS-001 | VERIFIED | Fresh install runbook | Doc review |
| REQ-QA-006 | İşletim / runbook dokümantasyonu | P06 | qa | REQ-OPS-008 | VERIFIED | Incident + upgrade | Doc review |
| REQ-QA-007 | Güvenlik tarama CI (deps, image) | P06 | qa | REQ-OPS-005 | VERIFIED | Critical CVEs fail | CI |
| REQ-QA-008 | Performans / smoke load | P06 | qa | REQ-LB-002 | VERIFIED | Baseline rapor | Load smoke |
| REQ-QA-009 | Gereksinim izlenebilirlik matrisi güncel | P01 | qa | — | VERIFIED | Her REQ bir PHASE’te | Traceability check |
| REQ-QA-010 | Uçtan uca production checklist | P06 | qa | tüm P01–P05 kritik | IMPLEMENTED | Checklist tamam | Sign-off |

---

## İzlenebilirlik özeti (aşama → birincil sahiplik)

| Aşama | REQ sayısı | Dosya |
|-------|------------|-------|
| P01 MVP | 61 | `plans/PHASE_01_MVP.md` |
| P02 SSL | 15 | `plans/PHASE_02_SSL.md` |
| P03 LB | 14 | `plans/PHASE_03_LOAD_BALANCER.md` |
| P04 WAF | 15 | `plans/PHASE_04_WAF.md` |
| P05 IDS | 14 | `plans/PHASE_05_IDS_IPS.md` |
| P06 Production | 28 | `plans/PHASE_06_PRODUCTION.md` |
| **Toplam** | **148** | örtüşmesiz birincil sahiplik |

Detaylı ID listeleri her `PHASE_*.md` içinde tek tek yazılır. `REQ-QA-009` her aşamada doğrulanır.

## Kapsam dışı (bilinçli)

- Nginx Plus özel API / dinamik upstream Plus-only özellikleri (OSS ile emülasyon belgelenir)
- Çoklu tenant SaaS faturalama
- Kubernetes Operator (ileride DEFERRED olabilir)
- Tam CDN / Anycast

## Değişiklik süreci

1. Yeni gereksinim → benzersiz `REQ-*` ID + aşama + test.
2. Kapsam değişikliği → `MASTER_PLAN` risk/kapsam güncellemesi + kullanıcı onayı.
3. `VERIFIED` yalnızca kabul kriteri + otomatik/manuel test kanıtı ile.
