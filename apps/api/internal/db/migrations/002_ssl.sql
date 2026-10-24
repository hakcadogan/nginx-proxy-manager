-- REQ-SSL-001..013 — certificates + host binding
-- +goose Up

CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    domains TEXT[] NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('upload', 'self_signed', 'private_ca', 'acme')),
    acme_challenge TEXT CHECK (acme_challenge IS NULL OR acme_challenge IN ('http-01', 'dns-01')),
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    issuer TEXT NOT NULL DEFAULT '',
    cert_path TEXT NOT NULL,
    key_path TEXT NOT NULL,
    auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
    renew_after_days INTEGER NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_certificates_not_after ON certificates (not_after);

ALTER TABLE proxy_hosts
    ADD COLUMN certificate_id UUID REFERENCES certificates(id) ON DELETE SET NULL;

CREATE TABLE acme_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    directory_url TEXT NOT NULL,
    eab_kid TEXT NOT NULL DEFAULT '',
    -- eab_hmac stored only as path reference; never log
    eab_hmac_path TEXT NOT NULL DEFAULT '',
    account_dir TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS certificate_id;
DROP TABLE IF EXISTS acme_accounts;
DROP TABLE IF EXISTS certificates;
