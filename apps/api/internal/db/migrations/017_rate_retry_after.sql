-- +goose Up
-- REQ-RATE-005 — Retry-After seconds on limit_req 429 responses
ALTER TABLE rate_limit_profiles
    ADD COLUMN IF NOT EXISTS retry_after_seconds INTEGER NOT NULL DEFAULT 1;

ALTER TABLE rate_limit_profiles
    DROP CONSTRAINT IF EXISTS rate_limit_profiles_retry_after_seconds_check;

ALTER TABLE rate_limit_profiles
    ADD CONSTRAINT rate_limit_profiles_retry_after_seconds_check
    CHECK (retry_after_seconds >= 1 AND retry_after_seconds <= 3600);

-- Seed: ~1/RPS (ceil), clamped 1..3600
UPDATE rate_limit_profiles
SET retry_after_seconds = GREATEST(1, LEAST(3600, CEIL(1.0 / NULLIF(requests_per_second, 0))::int))
WHERE retry_after_seconds = 1
  AND requests_per_second > 0
  AND requests_per_second < 1;

-- +goose Down
ALTER TABLE rate_limit_profiles DROP CONSTRAINT IF EXISTS rate_limit_profiles_retry_after_seconds_check;
ALTER TABLE rate_limit_profiles DROP COLUMN IF EXISTS retry_after_seconds;
