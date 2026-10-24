# PHASE_04_WAF — ModSecurity v3, OWASP CRS, Politikalar, Olaylar

**Durum:** GATE_PASSED (2026-10-22 — `scripts/p04-waf-gate.sh`)  
**Önkoşul:** P01 config pipeline; nginx imaj migration planı hazır  
**Sonraki:** `PHASE_05_IDS_IPS.md` (kullanıcı onayı gerekir)

## 1. Kapsam özeti

- ModSecurity v3 + nginx connector’lü data-plane imajı
- OWASP CRS pin’li kurulum
- Detection Only ve Blocking
- Host/global enable, paranoia level
- Kural ve path istisnaları
- Güvenlik olayları listesi/detay (maskeli)
- False-positive tuning iş akışı
- Bot UA kuralları (`REQ-RATE-004`)
- WAF audit log konfigürasyonu

## 2. Sahiplenilen gereksinimler

`REQ-WAF-001`, `REQ-WAF-002`, `REQ-WAF-003`, `REQ-WAF-004`, `REQ-WAF-005`, `REQ-WAF-006`, `REQ-WAF-007`, `REQ-WAF-008`, `REQ-WAF-009`, `REQ-WAF-010`, `REQ-WAF-011`, `REQ-WAF-012`, `REQ-RATE-004`, `REQ-RATE-010`, `REQ-API-007`, `REQ-UI-007`

**Sayı:** 15

## 3. Teknik uyumluluk (gizlenmez)

- Stok Nginx OSS paketinde ModSecurity **yok**.
- `nginx` ↔ `ModSecurity-nginx` connector sürümleri hizalanmalı; ABI kırılması imajı düşürür (RISK-01).
- CRS major upgrade’leri kural ID/davranış değiştirebilir → pin + migration notu.
- `SecRuleEngine Off|DetectionOnly|On` host bazlı include ile yönetilir.
- Performans: body inspection limitleri dokümante edilir.

## 4. Görev kırılımı

| # | Görev | REQ |
|---|-------|-----|
| 4.1 | Custom nginx+ModSec Dockerfile + CI smoke | WAF-001 |
| 4.2 | CRS fetch/pin + volume layout | WAF-002 |
| 4.3 | Policy model (engine mode, PL) | WAF-003…006 |
| 4.4 | Exception overlay generator | WAF-007,008 |
| 4.5 | Audit log → event ingest + mask | WAF-009,010,012 |
| 4.6 | Tuning UX (event → exception) | WAF-011 |
| 4.7 | Bad bot rules | RATE-004 |
| 4.8 | API + UI | API-007, UI-007 |
| 4.9 | Attack suite (SQLi/XSS sample) | WAF-003,004 |
| 4.10 | P01→P04 imaj migration runbook | OPS |

## 5. Varsayılan güvenlik duruşu

- Yeni host: **DetectionOnly** (false-positive öğrenme)
- Global Blocking’e geçiş: bilinçli Operator/Admin + checklist
- Exception’lar auditlenir

## 6. Kabul kriterleri

- [x] ModSec imajı health + modül yüklü
- [x] CRS kuralları yüklenir (versiyon raporu)
- [x] DetectionOnly: malicious request engellenmez (lab’da upstream 530 olabilir) + audit
- [x] Blocking: aynı request 403 + event
- [x] Rule ID exception overlay’e yazılır
- [x] Event detayında secret/password maskeli (unit)
- [x] UI’dan mode değiştir → apply → doğrulanır
- [x] UA allowlist (REQ-RATE-010) — bad-bot skipAfter + panel
- [x] ModSec global ayarlar + özel kurallar (REQ-WAF-017/018)

## 7. Doğrulama testleri

| Test | Tür |
|------|-----|
| Image module load | Smoke |
| Engine mode conf | Unit |
| Attack DetectionOnly/Blocking | E2E |
| Exception scoped | Integration |
| Masking | Unit |
| UI policy/events | Playwright |

## 8. Riskler

RISK-01, RISK-06; yüksek PL’de latency; log hacmi.

## 9. Çıkış

WAF kritik REQ `VERIFIED` (`scripts/p04-waf-gate.sh`) → P05 için kullanıcı onayı.

## 10. İmaj migration notu (P01→P04)

`deploy/docker/Dockerfile.nginx` artık `owasp/modsecurity-crs:4.20.0-nginx-alpine-202511100111` tabanlıdır (pin). Compose recreate: `docker compose up -d --build nginx`. CRS `/opt/owasp-crs`, overlay `/var/lib/nsp/modsec/overlay.conf`, motor dosyaları `engine-{DetectionOnly,On,Off}.conf`.
