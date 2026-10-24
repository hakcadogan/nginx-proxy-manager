# AGENTS.md — Nginx Security Platform

Bu dosya, bu repository üzerinde çalışan her AI ajanı ve geliştirici için **zorunlu** çalışma kurallarını tanımlar.

## Her oturumun başında (zorunlu)

1. `docs/REQUIREMENTS.md` dosyasını oku.
2. `plans/MASTER_PLAN.md` dosyasını oku.
3. Aktif aşama planını oku (`plans/PHASE_0X_*.md` — MASTER_PLAN’daki “Aktif Aşama” alanına bak).
4. `docs/SECURITY.md` içindeki güvenlik kurallarını gözden geçir.
5. Değişiklik yapılacak modülle ilgili mimariyi `docs/ARCHITECTURE.md` içinde doğrula.

Bu adımlar atlanamaz. Önceki oturum bağlamı bu zorunluluğu kaldırmaz.

## Her oturum sırasında (zorunlu)

- Yalnızca aktif aşama ve açıkça atanmış gereksinim ID’leri üzerinde çalış.
- Her uygulama değişikliği en az bir gereksinim ID’sine (`REQ-*`) bağlanmalı.
- Mock, stub, TODO veya “şimdilik boş” implementasyonlar **tamamlanmış özellik sayılmaz**.
- Gizli anahtarlar, sertifika private key’leri, parola ve token’lar asla loglanmaz.
- Nginx konfigürasyonu `nginx -t` (veya eşdeğeri) doğrulaması olmadan yayına alınmaz.
- Başarısız reload sonrası çalışan son bilinen iyi konfigürasyon korunur ve rollback uygulanır.
- Kontrol düzlemine sınırsız shell veya Docker socket erişimi verilmez.
- Kontrol düzlemi ile veri düzlemi ayrımı korunur.

## Her oturumun sonunda (zorunlu)

1. İlgili birim / entegrasyon / E2E testlerini çalıştır (veya neden çalıştırılamadığını kaydet).
2. Test edilmemiş özellikleri `VERIFIED` olarak işaretleme.
3. Tamamlanan / kısmi / engellenen gereksinimlerin durumunu `docs/REQUIREMENTS.md` ve aktif `plans/PHASE_*.md` içinde güncelle.
4. Teknik borç, risk veya kapsam sapmasını `plans/MASTER_PLAN.md` Riskler bölümüne ekle.
5. Uygulama koduna başlamadan önce kullanıcının onayını bekle — bu kural planlama dışı kodlama görevleri için de geçerlidir; kullanıcı açıkça kodlama istemedikçe yalnızca planlanan işi yap.

## Doküman öncelik sırası (çakışmada)

1. `docs/SECURITY.md` (güvenlik her zaman üstün)
2. `docs/REQUIREMENTS.md` (kapsam kaynağı)
3. `plans/MASTER_PLAN.md` + aktif `PHASE_*.md`
4. `docs/ARCHITECTURE.md`
5. `docs/API.md`

## Durum etiketleri

| Etiket | Anlam |
|--------|--------|
| `PLANNED` | Gereksinim tanımlı, uygulama yok |
| `IN_PROGRESS` | Aktif geliştirme |
| `IMPLEMENTED` | Kod var, testler henüz geçmedi / eksik |
| `VERIFIED` | Kabul kriteri + doğrulama testi geçti |
| `BLOCKED` | Teknik/ürün engeli; neden belgelenmeli |
| `DEFERRED` | Bilinçli olarak sonraki aşamaya ertelendi |

## Yasaklar

- Planlanmamış özellik eklemek
- Test edilmemiş özelliği `VERIFIED` işaretlemek
- Production secret’larını repository’ye commit etmek
- Docker socket’i uygulama container’ına mount etmek
- Kullanıcı onayı olmadan commit / push / release

## Referans dosyalar

| Dosya | Rol |
|-------|-----|
| `docs/REQUIREMENTS.md` | Tek kaynak gereksinim kataloğu |
| `docs/ARCHITECTURE.md` | Sistem mimarisi |
| `docs/SECURITY.md` | Güvenlik politikası |
| `docs/API.md` | API sözleşmesi özeti |
| `plans/MASTER_PLAN.md` | Aşamalar ve bağımlılıklar |
| `plans/PHASE_01_MVP.md` … `PHASE_06_PRODUCTION.md` | Aşama uygulama planları |
