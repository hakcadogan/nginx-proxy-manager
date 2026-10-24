-- REQ-LB-001 — optional per-member max_conns (nginx server max_conns=)
-- +goose Up
ALTER TABLE upstream_members
  ADD COLUMN IF NOT EXISTS max_conns INTEGER NOT NULL DEFAULT 0
    CHECK (max_conns >= 0 AND max_conns <= 100000);

-- +goose Down
ALTER TABLE upstream_members DROP COLUMN IF EXISTS max_conns;
