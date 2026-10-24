-- REQ-WAF-001..012, REQ-API-007 — WAF policies, exceptions, security events
-- +goose Up

CREATE TABLE waf_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'host')),
    host_id UUID REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    engine_mode TEXT NOT NULL DEFAULT 'DetectionOnly'
        CHECK (engine_mode IN ('Off', 'DetectionOnly', 'On')),
    paranoia_level INTEGER NOT NULL DEFAULT 1 CHECK (paranoia_level BETWEEN 1 AND 4),
    audit_relevant_only BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT waf_policies_host_scope CHECK (
        (scope = 'global' AND host_id IS NULL) OR
        (scope = 'host' AND host_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX waf_policies_one_global ON waf_policies ((scope)) WHERE scope = 'global';
CREATE UNIQUE INDEX waf_policies_one_per_host ON waf_policies (host_id) WHERE scope = 'host';

CREATE TABLE waf_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES waf_policies(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    path_prefix TEXT NOT NULL DEFAULT '',
    argument TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_waf_exceptions_policy ON waf_exceptions (policy_id);

CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'waf',
    host_id UUID REFERENCES proxy_hosts(id) ON DELETE SET NULL,
    domain TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    severity INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    uri TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    client_ip TEXT NOT NULL DEFAULT '',
    payload_summary TEXT NOT NULL DEFAULT '',
    unique_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_security_events_created ON security_events (created_at DESC);
CREATE INDEX idx_security_events_rule ON security_events (rule_id);
CREATE UNIQUE INDEX idx_security_events_unique ON security_events (unique_id) WHERE unique_id <> '';

ALTER TABLE proxy_hosts
    ADD COLUMN waf_enabled BOOLEAN NOT NULL DEFAULT TRUE;

INSERT INTO waf_policies (name, scope, enabled, engine_mode, paranoia_level)
VALUES ('default-global', 'global', TRUE, 'DetectionOnly', 1);

-- +goose Down
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS waf_enabled;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS waf_exceptions;
DROP TABLE IF EXISTS waf_policies;
