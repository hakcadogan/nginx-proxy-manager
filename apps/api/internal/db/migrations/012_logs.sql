-- REQ-OBS-006 file log rotation settings; REQ-PROXY-009 per-host access log format presets
ALTER TABLE proxy_hosts
  ADD COLUMN IF NOT EXISTS access_log_format TEXT NOT NULL DEFAULT 'main';

INSERT INTO platform_settings (key, value, updated_at) VALUES
  ('log_rotate_enabled', 'true', now()),
  ('log_rotate_max_mb', '100', now()),
  ('log_rotate_keep', '7', now()),
  ('log_rotate_interval_min', '60', now())
ON CONFLICT (key) DO NOTHING;
