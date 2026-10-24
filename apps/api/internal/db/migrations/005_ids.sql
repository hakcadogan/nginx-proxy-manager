-- REQ-IDS-005..008, REQ-API-008 — IP policies + CrowdSec decision cache
-- +goose Up

CREATE TABLE ip_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL CHECK (kind IN ('allow', 'deny', 'ban')),
    ip_cidr TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'crowdsec')),
    external_id TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ip_policies_kind ON ip_policies (kind);
CREATE INDEX idx_ip_policies_ip ON ip_policies (ip_cidr);
CREATE UNIQUE INDEX idx_ip_policies_crowdsec_ext ON ip_policies (external_id) WHERE external_id <> '';

-- +goose Down
DROP TABLE IF EXISTS ip_policies;
