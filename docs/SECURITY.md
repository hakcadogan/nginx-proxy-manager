# SECURITY.md — Nginx Security Platform

**Versiyon:** 1.0.0  
**Öncelik:** Çakışmada bu belge tüm diğer plan dosyalarından üstündür.

## 1. Temel ilkeler

1. **Kontrol / veri düzlemi ayrımı** — Yönetim düzlemi çökse bile trafik düzlemi son bilinen iyi konfigürasyonla çalışmaya devam eder.
2. **Least privilege** — Her bileşen yalnızca ihtiyacı olan dosya, ağ ve secret’a erişir.
3. **Doğrulama kapısı** — Nginx conf `nginx -t` geçmeden yayınlanmaz.
4. **Rollback zorunlu** — Başarısız reload’da last-good conf geri yüklenir.
5. **Secret hijyeni** — Private key, parola, token loglanmaz, commit edilmez, UI’da tam gösterilmez.
6. **Tamamlanmış ≠ mock** — Stub/TODO özellik güvenlik kontrolü sayılmaz.
7. **Test edilmeden VERIFIED yok**.

## 2. Yasaklar (hard rules)

| Yasak | Gerekçe |
|-------|---------|
| Uygulama container’ına Docker socket mount | Tam host/control kaçışı |
| API’den sınırsız shell / `os/exec` ile keyfi komut | RCE yüzeyi |
| Doğrulanmamış nginx conf reload | Trafik kesintisi / açık proxy |
| Başarısız apply sonrası bozuk conf bırakma | Kalıcı outage |
| Secret’ları access/audit/app log’a yazma | Sızıntı |
| Varsayılan zayıf admin parolası prod’da | Hesap ele geçirme |
| CRS/WAF’ı “kapatıp unutma” production default | Korumasız kenar |

## 3. Kimlik ve erişim

### Roller (MVP minimum)

| Rol | Özet |
|-----|------|
| `Admin` | Kullanıcı, sistem ayarları, tüm mutasyonlar |
| `Operator` | Proxy/SSL/LB/WAF/IDS operasyonları; kullanıcı yönetimi yok |
| `Viewer` | Salt okunur |

### Oturum

- Parola: **argon2id**.
- Oturum: **HttpOnly + Secure + SameSite=Lax cookie** (P01 kilidi; JWT kullanılmaz). Session ID Redis’te saklanır.
- CSRF: cookie oturumunda zorunlu double-submit header `X-CSRF-Token` (`REQ-AUTH-009`).
- Bootstrap: ilk admin tek seferlik setup token / interactive setup (`REQ-AUTH-005`).

### Sertleştirme (P06)

- Hesap kilitlenme, parola politikası, opsiyonel TOTP MFA, scoped API token’lar.

## 4. Konfigürasyon güvenliği

- Kullanıcı girdileri template’e **escape/allowlist** ile girer (`REQ-CFG-008`); panelden ham nginx snippet **kapalı** (P01 kilidi).
- Operatör volume drop-in: yalnızca NPM uyumlu **allowlist dosya adları** (`REQ-PROXY-021`, `data/nginx/custom/*.conf` isimleri sabit); rastgele `*.conf` glob yok; apply sırasında silinmez; `nginx -t` fail → rollback.
- Staging → validate → atomic publish.
- Config agent ayrı binary: conf yazma, `nginx -t`, reload; **Docker socket yok** (P01 kilidi).
- Agent network: yalnızca control bridge; internet yok (mümkünse).
- Redis P01’de session için zorunlu.

## 5. TLS ve anahtarlar

- Private key dosya izinleri kısıtlı volume’da.
- API response’ta private key **asla** dönülmez; download ayrı, audit’li, yetkili işlem olabilir (tercihen hiç export yok; regenerate).
- ACME hesap anahtarları secret store.
- Cloudflare API token: DNS edit scope minimum; secret file/env.
- Min TLS 1.2; zayıf cipher setleri yasak.

## 6. WAF ve IDS güvenlik politikası

- Yeni hostlarda WAF default: **Detection Only** (false-positive öğrenme), production checklist’te Blocking’e geçiş adımı (`REQ-QA-010`).
- WAF exception’lar auditlenir; geniş `remove by tag` dikkatle.
- CrowdSec allowlist kötüye kullanımına karşı Admin/Operator ayrımı.
- Güvenlik olaylarında hassas payload **maskelenir** (`REQ-WAF-010`).

## 7. Ağ ve container

- PostgreSQL / Redis portları host’a zorunlu değilse publish edilmez.
- Nginx yalnızca 80/443 (ve gerekirse management değil).
- API yalnızca internal + reverse proxy üzerinden expose (UI aynı origin veya sıkı CORS).
- Compose secret / env file; `.env` gitignore.
- Image’lar pin’li digest veya immutable tag politikası (P06).

## 8. Audit ve izleme

- Tüm mutasyonlar: actor, action, resource, before/after özeti, request_id, timestamp.
- Reload başarı/başarısızlık audit + metrik.
- Failed login audit.
- Yedekler şifreli veya en azından erişim kontrollü storage (P06).

## 9. Tedarik zinciri

- Go/npm bağımlılık tarama CI (`REQ-QA-007`).
- Base image CVE tarama.
- OWASP CRS ve CrowdSec hub sürüm pin + changelog review.

## 10. Olay müdahalesi (kısa)

1. Trafik: last-good conf / disable faulty host.
2. WAF: Detection ↔ Blocking acil anahtar (yetkili).
3. IDS: manuel ban / allowlist geçici.
4. Credential: rotate admin, ACME, Cloudflare, bouncer keys.
5. Post-incident: audit export + config version diff.

## 11. Güvenlik kabul kapıları (aşama)

| Aşama | Kapı |
|-------|------|
| P01 | Authz testleri, conf injection testleri, secret scan, rollback drill |
| P02 | Key leak test, ACME failure rollback |
| P03 | Upstream abuse (open proxy) negativ test |
| P04 | WAF bypass smoke, exception audit |
| P05 | Bouncer fail-open/fail-closed kararı belgelenir ve test edilir |
| P06 | MFA/token, backup encryption, image scan, E2E security checklist |
