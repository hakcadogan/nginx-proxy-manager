-- REQ-LB-001..011, REQ-PROXY-012 — upstream pools + members
-- +goose Up

CREATE TABLE upstreams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL DEFAULT 'round_robin'
        CHECK (algorithm IN (
            'round_robin', 'weighted_round_robin', 'least_conn',
            'ip_hash', 'hash', 'hash_consistent'
        )),
    hash_key TEXT NOT NULL DEFAULT '$request_uri',
    scheme TEXT NOT NULL DEFAULT 'http' CHECK (scheme IN ('http', 'https')),
    sni TEXT NOT NULL DEFAULT '',
    connect_timeout TEXT NOT NULL DEFAULT '5s',
    send_timeout TEXT NOT NULL DEFAULT '60s',
    read_timeout TEXT NOT NULL DEFAULT '60s',
    max_fails INTEGER NOT NULL DEFAULT 3 CHECK (max_fails >= 0),
    fail_timeout TEXT NOT NULL DEFAULT '10s',
    health_check_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    health_check_path TEXT NOT NULL DEFAULT '/',
    health_check_interval_sec INTEGER NOT NULL DEFAULT 10 CHECK (health_check_interval_sec >= 5),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE upstream_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    upstream_id UUID NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
    weight INTEGER NOT NULL DEFAULT 1 CHECK (weight >= 1 AND weight <= 1000),
    is_backup BOOLEAN NOT NULL DEFAULT FALSE,
    is_down BOOLEAN NOT NULL DEFAULT FALSE,
    is_drain BOOLEAN NOT NULL DEFAULT FALSE,
    last_check_at TIMESTAMPTZ,
    last_check_ok BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (upstream_id, host, port)
);

CREATE INDEX idx_upstream_members_upstream ON upstream_members (upstream_id);

ALTER TABLE proxy_hosts
    ADD COLUMN upstream_id UUID REFERENCES upstreams(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS upstream_id;
DROP TABLE IF EXISTS upstream_members;
DROP TABLE IF EXISTS upstreams;
