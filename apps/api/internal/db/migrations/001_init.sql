-- REQ-DATA-001, REQ-DATA-003, REQ-DATA-005
-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rate_limit_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    requests_per_second DOUBLE PRECISION NOT NULL DEFAULT 10,
    burst INTEGER NOT NULL DEFAULT 20,
    connections_per_ip INTEGER NOT NULL DEFAULT 20,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE proxy_hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    primary_domain TEXT NOT NULL UNIQUE,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    upstream_scheme TEXT NOT NULL DEFAULT 'http' CHECK (upstream_scheme IN ('http', 'https')),
    upstream_host TEXT NOT NULL,
    upstream_port INTEGER NOT NULL DEFAULT 80 CHECK (upstream_port > 0 AND upstream_port <= 65535),
    path_prefix TEXT NOT NULL DEFAULT '/',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    force_https BOOLEAN NOT NULL DEFAULT FALSE,
    websocket_support BOOLEAN NOT NULL DEFAULT TRUE,
    access_log_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    custom_headers JSONB NOT NULL DEFAULT '[]'::jsonb,
    locations JSONB NOT NULL DEFAULT '[]'::jsonb,
    rate_limit_profile_id UUID REFERENCES rate_limit_profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_proxy_hosts_domain ON proxy_hosts (primary_domain) WHERE deleted_at IS NULL;
CREATE INDEX idx_proxy_hosts_enabled ON proxy_hosts (enabled) WHERE deleted_at IS NULL;

CREATE TABLE config_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version INTEGER NOT NULL UNIQUE,
    checksum TEXT NOT NULL,
    rendered TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('staged', 'applied', 'rolled_back', 'failed')),
    message TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_created ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);

INSERT INTO rate_limit_profiles (name, requests_per_second, burst, connections_per_ip)
VALUES ('default', 10, 20, 20);

-- +goose Down
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS config_versions;
DROP TABLE IF EXISTS proxy_hosts;
DROP TABLE IF EXISTS rate_limit_profiles;
DROP TABLE IF EXISTS users;
