-- Proxy host advanced options — listen/http2/body/timeouts/grpc + trusted proxies
-- +goose Up

ALTER TABLE proxy_hosts
    ADD COLUMN IF NOT EXISTS listen_http BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS listen_https BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS http2 BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS client_max_body_size TEXT NOT NULL DEFAULT '10m',
    ADD COLUMN IF NOT EXISTS connect_timeout TEXT NOT NULL DEFAULT '5s',
    ADD COLUMN IF NOT EXISTS send_timeout TEXT NOT NULL DEFAULT '60s',
    ADD COLUMN IF NOT EXISTS read_timeout TEXT NOT NULL DEFAULT '60s',
    ADD COLUMN IF NOT EXISTS proxy_protocol TEXT NOT NULL DEFAULT 'http';

-- constrain proxy_protocol if not already constrained
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'proxy_hosts_proxy_protocol_check'
  ) THEN
    ALTER TABLE proxy_hosts
      ADD CONSTRAINT proxy_hosts_proxy_protocol_check
      CHECK (proxy_protocol IN ('http', 'grpc'));
  END IF;
END $$;

INSERT INTO platform_settings (key, value) VALUES
    ('trusted_proxies', ''),
    ('real_ip_header', 'X-Forwarded-For')
ON CONFLICT (key) DO NOTHING;

-- +goose Down
ALTER TABLE proxy_hosts
    DROP CONSTRAINT IF EXISTS proxy_hosts_proxy_protocol_check,
    DROP COLUMN IF EXISTS listen_http,
    DROP COLUMN IF EXISTS listen_https,
    DROP COLUMN IF EXISTS http2,
    DROP COLUMN IF EXISTS client_max_body_size,
    DROP COLUMN IF EXISTS connect_timeout,
    DROP COLUMN IF EXISTS send_timeout,
    DROP COLUMN IF EXISTS read_timeout,
    DROP COLUMN IF EXISTS proxy_protocol;
DELETE FROM platform_settings WHERE key IN ('trusted_proxies', 'real_ip_header');
