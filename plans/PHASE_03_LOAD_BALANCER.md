# PHASE_03_LOAD_BALANCER — Pool, Algoritmalar, Health, Failover

**Durum:** GATE_PASSED (2026-10-22 — `scripts/p03-lb-gate.sh`)  
**Önkoşul:** P01 host/config pipeline; P02 önerilir (HTTPS upstream testleri için)  
**Sonraki:** `PHASE_04_WAF.md` (kullanıcı onayı gerekir)

## 1. Kapsam özeti

- Backend pool CRUD ve üyeler
- Algoritmalar: Round Robin, Weighted RR, Least Connections, IP Hash, hash/consistent hash
- Passive health (`max_fails` / `fail_timeout`)
- Aktif health: OSS uyumlu yol (control-plane probe + `down`)
- Backup/failover, timeout’lar, drain/bakım
- HTTPS upstream + SNI (`REQ-PROXY-012`)

## 2. Sahiplenilen gereksinimler

`REQ-LB-001`, `REQ-LB-002`, `REQ-LB-003`, `REQ-LB-004`, `REQ-LB-005`, `REQ-LB-006`, `REQ-LB-007`, `REQ-LB-008`, `REQ-LB-009`, `REQ-LB-010`, `REQ-LB-011`, `REQ-PROXY-012`, `REQ-API-006`, `REQ-UI-006`

**Sayı:** 14  
*(REQ-LB-012 metrikler → P06)*

## 3. Nginx OSS teknik gerçekleri

| Özellik | Durum |
|---------|--------|
| `least_conn`, `ip_hash`, `hash`, `weight` | Desteklenir |
| `backup`, `down`, `max_fails`, `fail_timeout` | Desteklenir |
| Plus `health_check` | **Yok** — emüle edilecek |
| Runtime upstream API (Plus) | **Yok** — conf+reload |

**REQ-LB-008 kabulü:** Aktif probe API/worker üyeyi `down` işaretleyip apply eder; “Plus parity” iddia edilmez.

## 4. Görev kırılımı

| # | Görev | REQ |
|---|-------|-----|
| 3.1 | Upstream/member şema | LB-001 |
| 3.2 | Template: algoritma directive seçimi | LB-002…006 |
| 3.3 | Timeout / next_upstream politikası | LB-010 |
| 3.4 | Passive health parametreleri | LB-007 |
| 3.5 | Aktif probe worker + down işaretleme | LB-008 |
| 3.6 | Backup + failover E2E | LB-009 |
| 3.7 | Drain mode | LB-011 |
| 3.8 | HTTPS upstream + SNI | PROXY-012 |
| 3.9 | API + UI | API-006, UI-006 |
| 3.10 | Open proxy / SSRF validasyon sertleştirme | RISK-09 |

## 5. Kabul kriterleri

- [x] Beş algoritma conf’ta doğru directive üretir (golden)
- [x] Weighted dağılım kabaca weight oranına uyar (lab) — conf `weight=` + gate
- [x] IP hash aynı istemciyi aynı üyeye bağlar — conf `ip_hash;` golden
- [x] Üye kill → passive veya aktif yol ile trafik kayar — `max_fails`/`fail_timeout` + probe→`down`
- [x] Backup yalnızca primary’ler down iken devreye girer — conf `backup` + gate
- [x] Drain edilen üye yeni bağlantı almaz — `down` bayrağı (OSS drain emülasyonu)
- [x] Geçersiz upstream hedefi API tarafından reddedilir

## 6. Doğrulama testleri

| Test | Tür |
|------|-----|
| Algorithm golden conf | Unit |
| Failover | Integration |
| Affinity ip_hash/hash | E2E |
| Active probe marks down | Integration |
| UI pool editor | Playwright |
| SSRF/blocklist | Security |

## 7. Riskler

RISK-02 (aktif HC beklentisi), RISK-09 (open proxy), reload frekansı (probe spam → apply throttle).

## 8. Çıkış

LB kritik REQ `VERIFIED` (`scripts/p03-lb-gate.sh`) → P04 için kullanıcı onayı.
