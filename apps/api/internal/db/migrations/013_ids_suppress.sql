-- REQ-IDS-008: panelden silinen CrowdSec kararları sync ile geri gelmesin
CREATE TABLE IF NOT EXISTS ip_policy_suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_cidr TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ip_policy_suppressions_ext_uidx
  ON ip_policy_suppressions (external_id) WHERE external_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS ip_policy_suppressions_ip_uidx
  ON ip_policy_suppressions (ip_cidr);
