# Incident runbook özeti (REQ-QA-006)

Tam güvenlik politikası: `docs/SECURITY.md`.

## Hızlı kontrol listesi

1. Panel erişimi / login lockout
2. `GET /metrics` — `nsp_config_reload_total{result="failed"}`, cert expiry
3. `GET /api/v1/config/status` ve son sürümler
4. WAF Blocking host’lar — false positive?
5. IDS deny sync — fail-closed mi?
6. Gerekirse `POST /api/v1/config/rollback`
7. Olayı audit log’a işle; secret’ları loglama

## MFA kaybı

Admin başka bir admin ile kullanıcı unlock / MFA disable (TOTP doğrulamalı) — tek admin senaryosunda bootstrap token ile kurtarma lab prosedürü.
