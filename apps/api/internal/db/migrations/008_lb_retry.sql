-- Upstream retry policy (proxy_next_upstream) — REQ-LB-013
-- +goose Up

ALTER TABLE upstreams
    ADD COLUMN IF NOT EXISTS next_upstream TEXT NOT NULL DEFAULT 'error timeout http_502 http_503 http_504',
    ADD COLUMN IF NOT EXISTS next_upstream_tries INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_upstream_timeout TEXT NOT NULL DEFAULT '0';

-- +goose Down
ALTER TABLE upstreams
    DROP COLUMN IF EXISTS next_upstream,
    DROP COLUMN IF EXISTS next_upstream_tries,
    DROP COLUMN IF EXISTS next_upstream_timeout;
