-- ACME ops history + cert revisions — REQ-SSL-015..017
-- +goose Up

CREATE TABLE IF NOT EXISTS acme_operations (
    id BIGSERIAL PRIMARY KEY,
    certificate_id UUID REFERENCES certificates(id) ON DELETE SET NULL,
    operation TEXT NOT NULL CHECK (operation IN ('issue', 'renew', 'rollback')),
    challenge TEXT NOT NULL DEFAULT '',
    domains TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK (status IN ('success', 'failure')),
    error_message TEXT NOT NULL DEFAULT '',
    actor_email TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_acme_operations_created ON acme_operations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_acme_operations_cert ON acme_operations (certificate_id);

-- +goose Down
DROP TABLE IF EXISTS acme_operations;
