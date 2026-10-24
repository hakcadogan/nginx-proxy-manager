-- REQ-PROXY-009 — per-host error_log (alongside global error.log)
ALTER TABLE proxy_hosts
  ADD COLUMN IF NOT EXISTS error_log_enabled BOOLEAN NOT NULL DEFAULT true;
