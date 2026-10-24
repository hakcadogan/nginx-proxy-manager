# PHASE_02_SSL — ACME, Let's Encrypt, Manuel ve DNS Sertifikaları

**Durum:** GATE PASSED (lab) — canlı Let's Encrypt staging için genel DNS gerekir; kod + mock/gate hazır  
**Önkoşul:** `PHASE_01_MVP` kapısı tamam (`REQ-CFG-*` VERIFIED)  
**Sonraki:** `PHASE_03_LOAD_BALANCER.md`

## 1. Kapsam özeti

- Manuel PEM upload, self-signed, private CA imza
- Let's Encrypt HTTP-01 ve DNS-01
- Cloudflare DNS API entegrasyonu
- Wildcard (yalnızca DNS-01)
- Otomatik yenileme, envanter, expiry uyarıları
- TLS politika (min sürüm/cipher)
- Private key secret yönetimi
- Challenge sırasında güvenli conf/reload

## 2. Sahiplenilen gereksinimler

`REQ-SSL-001`, `REQ-SSL-002`, `REQ-SSL-003`, `REQ-SSL-004`, `REQ-SSL-005`, `REQ-SSL-006`, `REQ-SSL-007`, `REQ-SSL-008`, `REQ-SSL-009`, `REQ-SSL-010`, `REQ-SSL-011`, `REQ-SSL-012`, `REQ-SSL-013`, `REQ-API-005`, `REQ-UI-005`

**Sayı:** 15  
*(REQ-SSL-014 OCSP → P06)*

## 3. Dışı

- OCSP stapling (P06)
- Çoklu ACME sağlayıcı marketplace (Let’s Encrypt + staging yeterli; diğer CA EAB ile opsiyonel `REQ-SSL-010`)

## 4. Görev kırılımı

| # | Görev | REQ | Not |
|---|-------|-----|-----|
| 2.1 | Certificate entity + storage layout | SSL-013, DATA | Key permissions |
| 2.2 | Manuel upload + PEM validate | SSL-001 | Chain check |
| 2.3 | Self-signed generator | SSL-002 | |
| 2.4 | Private CA sign flow | SSL-003 | CA secret |
| 2.5 | ACME client entegrasyonu | SSL-010 | Staging default |
| 2.6 | HTTP-01 challenge path + conf | SSL-004, SSL-011 | Rollback |
| 2.7 | DNS-01 + Cloudflare provider | SSL-005, SSL-006 | Token secret |
| 2.8 | Wildcard issue UI guard | SSL-007, RISK-12 | HTTP-01 disable |
| 2.9 | Renewal worker / scheduler | SSL-008 | |
| 2.10 | Inventory + expiry warnings | SSL-009 | |
| 2.11 | TLS params in templates | SSL-012 | |
| 2.12 | API + UI | API-005, UI-005 | E2E staging |
| 2.13 | Chain/SAN validate + unused list | SSL-015,018 | |
| 2.14 | Atomic write + cert rollback | SSL-016 | |
| 2.15 | ACME ops history + self-signed warn | SSL-017,019 | |
| 2.16 | Auto-renew worker (ACME issue) | SSL-008 | |

## 5. ACME yaşam döngüsü (zorunlu tasarım)

```
issue → place challenge → validate conf → reload
     → ACME finalize → store cert/key → bind host
     → render TLS conf → validate → reload
failure at any reload step → rollback last-good
renewal failure → keep existing cert + alert
```

HTTP-01: `.well-known/acme-challenge/` yalnızca gerekli host/path.  
DNS-01: TXT create → poll → delete (best effort) → audit.

## 6. Kabul kriterleri

- [ ] Staging ACME HTTP-01 ile gerçek sertifika — **kod hazır; canlı staging public DNS ister** (`IMPLEMENTED`)
- [x] Staging DNS-01 + Cloudflare API + **mock provider** (`ACME_USE_MOCK_DNS`)
- [x] Wildcard yalnızca DNS-01 ile (API 400 guard)
- [x] Self-signed/upload/private-CA → host bind → conf’te `listen 443 ssl` + TLS 1.2/1.3
- [x] Yenileme eşiği birim testi (`ShouldRenew`) + envanter `days_remaining`/`expiring_soon`
- [x] Private key API response’ta yok (leak test)
- [x] ACME challenge location conf’te; conf apply hâlâ validate+rollback pipeline kullanır

## 10. Doğrulama komutları

```bash
bash scripts/p02-ssl-gate.sh
cd apps/api && go test ./internal/certs ./internal/nginxcfg
```

Panel SSL: http://localhost:28080/ssl — HTTPS data plane: https://localhost:8443

## 7. Doğrulama testleri

| Test | Tür |
|------|-----|
| PEM parse/reject | Unit |
| Self-signed openssl | Integration |
| ACME HTTP-01 staging | E2E |
| Cloudflare TXT mock | Integration |
| Renewal threshold | Unit |
| Key permission / leak | Security |
| UI issue/upload | Playwright |

## 8. Riskler

RISK-04, RISK-05, RISK-12; ayrıca rate limit Let’s Encrypt (staging kullan).

## 9. Çıkış

SSL kritik REQ `VERIFIED` → P03.
