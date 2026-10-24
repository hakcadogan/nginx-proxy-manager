-- REQ-LB-008/011 — manual disable must not be cleared by active health probe
-- +goose Up
ALTER TABLE upstream_members
  ADD COLUMN IF NOT EXISTS admin_disabled BOOLEAN NOT NULL DEFAULT false;

-- Backfill: currently down (non-drain) members are treated as admin-disabled so
-- the next successful probe does not silently re-enable operator intent.
UPDATE upstream_members
SET admin_disabled = true
WHERE is_down = true AND is_drain = false;

-- +goose Down
ALTER TABLE upstream_members DROP COLUMN IF EXISTS admin_disabled;
