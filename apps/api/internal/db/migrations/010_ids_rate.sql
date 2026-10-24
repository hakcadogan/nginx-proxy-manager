-- IDS ban history + protected CIDRs + host allowed_methods — REQ-IDS-012..014, REQ-RATE-007
-- +goose Up

CREATE TABLE IF NOT EXISTS ip_policy_history (
    id BIGSERIAL PRIMARY KEY,
    policy_id UUID,
    action TEXT NOT NULL CHECK (action IN ('create', 'delete', 'expire', 'sync')),
    kind TEXT NOT NULL,
    ip_cidr TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    country_code TEXT NOT NULL DEFAULT '',
    actor_email TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ip_policy_history_created ON ip_policy_history (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_policy_history_ip ON ip_policy_history (ip_cidr);

ALTER TABLE proxy_hosts
    ADD COLUMN IF NOT EXISTS allowed_methods JSONB NOT NULL DEFAULT '[]'::jsonb;

INSERT INTO platform_settings (key, value) VALUES
    ('ids_protected_cidrs', '127.0.0.1,::1'),
    ('ids_require_trusted_proxies_note', 'true')
ON CONFLICT (key) DO NOTHING;

-- Seed infra allowlist (skip if already present)
INSERT INTO ip_policies (kind, ip_cidr, reason, source)
SELECT 'allow', '127.0.0.1', 'protected-loopback', 'manual'
WHERE NOT EXISTS (SELECT 1 FROM ip_policies WHERE kind='allow' AND ip_cidr='127.0.0.1');

INSERT INTO ip_policies (kind, ip_cidr, reason, source)
SELECT 'allow', '::1', 'protected-loopback', 'manual'
WHERE NOT EXISTS (SELECT 1 FROM ip_policies WHERE kind='allow' AND ip_cidr='::1');

-- +goose Down
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS allowed_methods;
DROP TABLE IF EXISTS ip_policy_history;
DELETE FROM platform_settings WHERE key IN ('ids_protected_cidrs', 'ids_require_trusted_proxies_note');
