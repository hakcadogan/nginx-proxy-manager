-- WAF anomaly thresholds + host-scoped exceptions — REQ-WAF-013..016
-- +goose Up

ALTER TABLE waf_policies
    ADD COLUMN IF NOT EXISTS inbound_anomaly_score_threshold INTEGER NOT NULL DEFAULT 5
        CHECK (inbound_anomaly_score_threshold BETWEEN 1 AND 10000),
    ADD COLUMN IF NOT EXISTS outbound_anomaly_score_threshold INTEGER NOT NULL DEFAULT 4
        CHECK (outbound_anomaly_score_threshold BETWEEN 1 AND 10000);

ALTER TABLE waf_exceptions
    ADD COLUMN IF NOT EXISTS host_id UUID REFERENCES proxy_hosts(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_waf_exceptions_host ON waf_exceptions (host_id);

-- +goose Down
ALTER TABLE waf_exceptions DROP COLUMN IF EXISTS host_id;
ALTER TABLE waf_policies
    DROP COLUMN IF EXISTS inbound_anomaly_score_threshold,
    DROP COLUMN IF EXISTS outbound_anomaly_score_threshold;
