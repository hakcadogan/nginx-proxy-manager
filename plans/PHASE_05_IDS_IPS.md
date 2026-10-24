# PHASE_05_IDS_IPS — CrowdSec, Bouncer, IP Politikaları

**Durum:** GATE_PASSED (2026-10-22 — `scripts/p05-ids-gate.sh`)  
**Önkoşul:** P01 access log yolları; P04 ile olay modeli uyumu önerilir  
**Sonraki:** `PHASE_06_PRODUCTION.md` (kullanıcı onayı gerekir)

## 1. Kapsam özeti

- CrowdSec engine container + hub koleksiyonları (nginx/http)
- Nginx log acquisition
- Bouncer entegrasyonu (tek tip seçim)
- Otomatik IP engelleme
- Manuel ban / unban / TTL
- Allowlist ve denylist
- Karar/alert panosu
- Bouncer API key secret yönetimi
- Birleşik güvenlik olay görünümü (`REQ-OBS-003`)

## 2. Sahiplenilen gereksinimler

`REQ-IDS-001`, `REQ-IDS-002`, `REQ-IDS-003`, `REQ-IDS-004`, `REQ-IDS-005`, `REQ-IDS-006`, `REQ-IDS-007`, `REQ-IDS-008`, `REQ-IDS-009`, `REQ-IDS-010`, `REQ-IDS-011`, `REQ-IDS-017`, `REQ-IDS-018`, `REQ-IDS-019`, `REQ-OBS-003`, `REQ-API-008`, `REQ-UI-008`

**Sayı:** 17

## 3. Bouncer seçim kararı (KİLİTLİ — 2026-10-22)

| Seçenek | Karar |
|---------|--------|
| CrowdSec nginx Lua bouncer | **Seçilmedi** — ModSec imajına Lua/OpenResty eklemek RISK-01 ile çakışır |
| Firewall bouncer (nftables) | **Seçilmedi** — host NET_ADMIN / Docker Desktop kısıtı |
| **Kontrol düzlemi nginx deny sync** | **Seçildi** — LAPI decisions + `ip_policies` → conf `allow`/`deny` → validate/apply |

**Fail modu (RISK-07):** Varsayılan **fail-closed** — LAPI erişilemezse son bilinen kararlar DB’de kalır ve conf’tan silinmez. `IDS_FAIL_OPEN=true` ile LAPI hatasında yalnızca manuel politikalar uygulanır (dokümante lab seçeneği).

## 4. WAF ile ilişki

- WAF (ModSec) request payload imzaları; CrowdSec davranış/tekrarlayan kötüye kullanım.
- Allowlist her iki yolda da engeli keser (nginx `allow` önce).
- Birleşik `security-events` API kaynak etiketi: `waf` | `crowdsec`.

## 5. Görev kırılımı

| # | Görev | REQ |
|---|-------|-----|
| 5.1 | CrowdSec compose + health | IDS-001 |
| 5.2 | Acquisition (nginx log volume) | IDS-002 |
| 5.3 | Hub collections pin | IDS-010 |
| 5.4 | Bouncer key + LAPI (internal) | IDS-003,011 |
| 5.5 | Decision sync → nginx deny | IDS-004 |
| 5.6 | Manual ban/unban/TTL API | IDS-005,008 |
| 5.7 | Allow/deny lists | IDS-006,007 |
| 5.8 | Decisions UI (IP arama, toplu seçim/silme + onay) | IDS-009, IDS-008, UI-008 |
| 5.9 | Unified security events | OBS-003, API-008 |
| 5.10 | Fail-open/closed belgeleme + gate | RISK-07 |
| 5.11 | Ban history + timeline UI | IDS-012,013 |
| 5.12 | Protected CIDRs + trusted-proxy uyarı | IDS-014,015 |
| 5.13 | GeoIP ülke kodu (MMDB) | IDS-016 DEFERRED |

## 6. Ağ

- LAPI host’a publish edilmez; yalnızca `control` network (`crowdsec:8080`).
- CrowdSec hub için çıkış (koleksiyon kurulumu); offline pin dokümante.

## 7. Kabul kriterleri

- [x] Engine log okuyor; scenario’lar yüklü
- [x] Eşik aşıldığında / sync sonrası IP engellenir (conf deny)
- [x] Manuel ban conf’ta; unban kaldırır
- [x] Allowlist’teki IP deny render’a girmez
- [x] Denylist anında blok (conf)
- [x] Panelde karar listesi
- [x] Bouncer key secret’ta; log’da yok
- [x] LAPI dışarıya kapalı (port publish yok)
- [x] Ban history API (`/ids/history`)
- [x] Korumalı CIDR ban reddi + CrowdSec skip
- [x] Tespit eşikleri UI + crowdsec-agent apply (REQ-IDS-017)
- [x] CSV/toplu IP ekleme + listede gerekçe kolonu (REQ-IDS-018)
- [ ] GeoIP (DEFERRED)

## 8. Doğrulama testleri

| Test | Tür |
|------|-----|
| Acquisition / collections | Integration |
| Manual ban conf | E2E gate |
| Allowlist precedence | Unit + gate |
| Secret leak | Security |
| LAPI not published | Network gate |
| Unified events source= | API |

## 9. Riskler

RISK-07, yanlış allowlist ile koruma delme, log format değişince acquisition kırılması.

## 10. Çıkış

IDS kritik REQ `VERIFIED` (`scripts/p05-ids-gate.sh`) → P06 için kullanıcı onayı.
