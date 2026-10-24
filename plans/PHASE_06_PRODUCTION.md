# PHASE_06_PRODUCTION — Sertleştirme, İzleme, Yedekleme, E2E

**Durum:** GATE_PASSED (lab) — QA-010 kullanıcı sign-off bekliyor  
**Önkoşul:** P01–P05 kritik yollar `VERIFIED`  
**Sonraki:** Production sign-off / bakım modu

## 1. Kapsam özeti

- RBAC sertleştirme (kilitlenme, MFA opsiyonel, scoped API token)
- Metrikler (Prometheus), alertler
- Backup / restore (DB + conf + cert meta)
- Log retention, güvenlik header preset’leri
- Soft challenge 429 politikası, limit metrikleri
- Kaynak limitleri, non-root, güncelleme prosedürü
- Güvenlik tarama CI, load smoke
- Uçtan uca production checklist
- OCSP stapling (destekleniyorsa), LB metrikleri

## 2. Sahiplenilen gereksinimler

`REQ-PROXY-013`, `REQ-PROXY-014`, `REQ-PROXY-015`, `REQ-PROXY-016`, `REQ-PROXY-017`, `REQ-PROXY-018`, `REQ-PROXY-019`, `REQ-PROXY-020`, `REQ-PROXY-021`, `REQ-LB-012`, `REQ-LB-013`, `REQ-WAF-013`, `REQ-WAF-014`, `REQ-WAF-015`, `REQ-WAF-016`, `REQ-SSL-014`, `REQ-RATE-005`, `REQ-RATE-006`, `REQ-API-012`, `REQ-API-013`, `REQ-API-014`, `REQ-UI-009`, `REQ-UI-010`, `REQ-DATA-006`, `REQ-DATA-007`, `REQ-AUTH-006`, `REQ-AUTH-007`, `REQ-AUTH-008`, `REQ-OPS-007`, `REQ-OPS-008`, `REQ-OPS-009`, `REQ-OBS-001`, `REQ-OBS-004`, `REQ-OBS-005`, `REQ-OBS-006`, `REQ-OBS-007`, `REQ-QA-006`, `REQ-QA-007`, `REQ-QA-008`, `REQ-QA-010`

**Sayı:** 40

## 3. Production checklist (`REQ-QA-010`)

- [x] Tüm P01–P05 kritik REQ `VERIFIED`
- [x] WAF Blocking politika kararı (host bazlı) gözden geçirildi
- [x] TLS min 1.2; zayıf cipher yok
- [x] Default admin bootstrap kapatıldı (kullanıcı oluşturulmuş ortam)
- [x] Secret’lar rotate edilebilir; örnek değer prod’da yok (lab `.env`)
- [x] Backup alınır (`GET /api/v1/backup`); restore runbook + settings restore
- [x] Upgrade runbook (`docs/runbooks/UPGRADE.md`)
- [x] Metrics scrape + alert counters (reload fail, cert expiry)
- [x] Dependency/image scan CI job (`security-scan`); pgx bumped
- [x] E2E suite / P06 gate yeşil (`scripts/p06-production-gate.sh`)
- [ ] SECURITY.md olay runbook okundu — **kullanıcı imzası**

## 4. Görev kırılımı

| # | Görev | REQ | Durum |
|---|-------|-----|-------|
| 6.1 | Parola politikası + lockout | AUTH-006 | VERIFIED |
| 6.2 | TOTP MFA | AUTH-007 | VERIFIED |
| 6.3 | Scoped API tokens | AUTH-008 | VERIFIED |
| 6.4 | User admin UI | UI-009 | VERIFIED |
| 6.5 | Prometheus metrics + dash | OBS-001, UI-010, LB-012, RATE-006 | VERIFIED |
| 6.6 | Alerts (expiry, reload) | OBS-007 | VERIFIED |
| 6.7 | Backup/restore API + job | OBS-004/005, API-014, DATA-007 | OBS-004/API-014/DATA-007 VERIFIED; OBS-005 IMPLEMENTED |
| 6.8 | Retention + file log rotate (panel `settings/logs`) | DATA-006, OBS-006 | VERIFIED |
| 6.9 | Security headers preset | PROXY-013 | VERIFIED |
| 6.10 | 429 challenge policy | RATE-005 | VERIFIED |
| 6.11 | Idempotency + API rate limit | API-012,013 | VERIFIED |
| 6.12 | Resource limits, non-root | OPS-007,009 | VERIFIED |
| 6.13 | Upgrade procedure | OPS-008, QA-006 | VERIFIED |
| 6.14 | OCSP if feasible | SSL-014 | VERIFIED |
| 6.15 | Scan CI + load smoke | QA-007,008 | VERIFIED |
| 6.16 | Sign-off checklist | QA-010 | IMPLEMENTED (imza bekliyor) |

## 5. Kabul kriterleri

- [x] MFA enforce edilebilir ortamda login E2E
- [x] Backup artifact üretilir; restore yolu runbook’ta
- [x] `/metrics` scrape
- [x] Cert expiry / reload fail alert metrikleri
- [x] Compose resource limits tanımlı
- [x] Upgrade runbook mevcut
- [ ] QA-010 checklist kullanıcı imzası
- [x] Hiçbir mock “VERIFIED” değil

## 6. Doğrulama testleri

| Test | Tür | Sonuç |
|------|-----|-------|
| MFA enroll/login | E2E | PASS |
| Backup export | E2E | PASS (`p06-production-gate.sh`) |
| Metrics contract | Integration | PASS |
| API idempotency | Integration | PASS |
| Lockout / password policy | Security | PASS (unit + surface) |
| Image/dep scan | CI | job eklendi |
| Load smoke | Perf | PASS (`p06-load-smoke.sh`) |
| Full regression | E2E | P06 gate PASS |

## 7. Riskler

Operasyonel karmaşıklık (RISK-11); MFA kayıp kurtarma prosedürü; backup’ta private key sızıntısı (şifreleme/erişim kontrolü) — key’ler backup JSON’da yok.

## 8. Çıkış

`scripts/p06-production-gate.sh` yeşil. Kullanıcı QA-010 imzasından sonra bakım / sonraki major (K8s vb. DEFERRED).
