package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

func (s *Store) ListIPPolicies(ctx context.Context, kind string) ([]models.IPPolicy, error) {
	items, _, err := s.ListIPPoliciesPage(ctx, kind, "", 0, 0)
	return items, err
}

// ListIPPoliciesPage returns filtered/paginated decisions (REQ-IDS-009).
// perPage<=0 returns all matching rows (used by render/sync).
func (s *Store) ListIPPoliciesPage(ctx context.Context, kind, q string, page, perPage int) ([]models.IPPolicy, int, error) {
	where := `WHERE (expires_at IS NULL OR expires_at > now())`
	args := []any{}
	n := 0
	if kind != "" {
		n++
		args = append(args, kind)
		where += fmt.Sprintf(` AND kind = $%d`, n)
	}
	q = strings.TrimSpace(q)
	if q != "" {
		n++
		args = append(args, "%"+strings.ToLower(q)+"%")
		where += fmt.Sprintf(` AND (lower(ip_cidr) LIKE $%d OR lower(reason) LIKE $%d OR lower(source) LIKE $%d)`, n, n, n)
	}
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ip_policies `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	sql := `
		SELECT id, kind, ip_cidr, reason, source, external_id, expires_at, created_by, created_at, updated_at
		FROM ip_policies ` + where + ` ORDER BY created_at DESC, kind`
	if perPage > 0 {
		if page < 1 {
			page = 1
		}
		if perPage > 200 {
			perPage = 200
		}
		offset := (page - 1) * perPage
		n++
		args = append(args, perPage)
		sql += fmt.Sprintf(` LIMIT $%d`, n)
		n++
		args = append(args, offset)
		sql += fmt.Sprintf(` OFFSET $%d`, n)
	}
	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.IPPolicy
	for rows.Next() {
		p, err := scanIPPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

func (s *Store) GetIPPolicy(ctx context.Context, id uuid.UUID) (models.IPPolicy, error) {
	row := s.Pool.QueryRow(ctx, `
		SELECT id, kind, ip_cidr, reason, source, external_id, expires_at, created_by, created_at, updated_at
		FROM ip_policies WHERE id=$1`, id)
	p, err := scanIPPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) CreateIPPolicy(ctx context.Context, p models.IPPolicy) (models.IPPolicy, error) {
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO ip_policies (kind, ip_cidr, reason, source, external_id, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, kind, ip_cidr, reason, source, external_id, expires_at, created_by, created_at, updated_at`,
		p.Kind, p.IPCIDR, p.Reason, p.Source, p.ExternalID, p.ExpiresAt, p.CreatedBy,
	).Scan(&p.ID, &p.Kind, &p.IPCIDR, &p.Reason, &p.Source, &p.ExternalID, &p.ExpiresAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

func (s *Store) DeleteIPPolicy(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM ip_policies WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteIPPolicyByExternalID(ctx context.Context, externalID string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM ip_policies WHERE external_id=$1`, externalID)
	return err
}

// SuppressIPPolicy marks an IP/external decision so CrowdSec sync will not re-insert it (REQ-IDS-008).
func (s *Store) SuppressIPPolicy(ctx context.Context, ipCIDR, externalID, reason string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO ip_policy_suppressions (ip_cidr, external_id, reason)
		VALUES ($1,$2,$3)
		ON CONFLICT (ip_cidr) DO UPDATE SET external_id=EXCLUDED.external_id, reason=EXCLUDED.reason, created_at=now()`,
		strings.TrimSpace(ipCIDR), strings.TrimSpace(externalID), strings.TrimSpace(reason))
	return err
}

func (s *Store) IsIPPolicySuppressed(ctx context.Context, ipCIDR, externalID string) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM ip_policy_suppressions
		WHERE ip_cidr=$1 OR ($2 <> '' AND external_id=$2)`,
		strings.TrimSpace(ipCIDR), strings.TrimSpace(externalID)).Scan(&n)
	return n > 0, err
}

// ClearSuppressionsNotIn removes suppressions whose CrowdSec decision is gone (allow re-ban later).
func (s *Store) ClearSuppressionsNotIn(ctx context.Context, keepExternalIDs []string) error {
	if len(keepExternalIDs) == 0 {
		_, err := s.Pool.Exec(ctx, `DELETE FROM ip_policy_suppressions WHERE external_id <> ''`)
		return err
	}
	_, err := s.Pool.Exec(ctx, `
		DELETE FROM ip_policy_suppressions
		WHERE external_id <> '' AND NOT (external_id = ANY($1))`, keepExternalIDs)
	return err
}

// UpsertCrowdSecDecision inserts or refreshes a crowdsec-sourced ban/deny.
// Protected CIDRs and panel-suppressed IPs are skipped (REQ-IDS-014, REQ-IDS-008).
func (s *Store) UpsertCrowdSecDecision(ctx context.Context, externalID, ip, reason string, expires *time.Time) error {
	protected, _ := s.GetSetting(ctx, "ids_protected_cidrs")
	if err := nginxcfg.ValidateProtectedBan(ip, protected); err != nil {
		return nil // skip silently — never ban loopback/management
	}
	if ok, _ := s.IsIPPolicySuppressed(ctx, ip, externalID); ok {
		return nil
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE ip_policies SET ip_cidr=$1, reason=$2, expires_at=$3, updated_at=now()
		WHERE external_id=$4 AND source='crowdsec'`, ip, reason, expires, externalID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO ip_policies (kind, ip_cidr, reason, source, external_id, expires_at)
		VALUES ('ban', $1, $2, 'crowdsec', $3, $4)`, ip, reason, externalID, expires)
	if err != nil {
		return err
	}
	_ = s.InsertIPPolicyHistory(ctx, models.IPPolicyHistory{
		Action: "sync", Kind: "ban", IPCIDR: ip, Reason: reason, Source: "crowdsec",
	})
	return nil
}

func (s *Store) ListSecurityEventsFiltered(ctx context.Context, source string, limit, offset int) ([]models.SecurityEvent, error) {
	return s.SearchSecurityEvents(ctx, SecurityEventFilter{Source: source, Limit: limit, Offset: offset})
}

func (s *Store) PurgeExpiredIPPolicies(ctx context.Context) (int64, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, kind, ip_cidr, reason, source FROM ip_policies
		WHERE expires_at IS NOT NULL AND expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var kind, ip, reason, source string
		if err := rows.Scan(&id, &kind, &ip, &reason, &source); err != nil {
			return 0, err
		}
		pid := id
		_ = s.InsertIPPolicyHistory(ctx, models.IPPolicyHistory{
			PolicyID: &pid, Action: "expire", Kind: kind, IPCIDR: ip, Reason: reason, Source: source,
		})
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM ip_policies WHERE expires_at IS NOT NULL AND expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) DeleteCrowdSecPoliciesNotIn(ctx context.Context, keepExternalIDs []string) error {
	var rows pgx.Rows
	var err error
	if len(keepExternalIDs) == 0 {
		rows, err = s.Pool.Query(ctx, `SELECT id, kind, ip_cidr, reason, source FROM ip_policies WHERE source='crowdsec'`)
	} else {
		rows, err = s.Pool.Query(ctx, `
			SELECT id, kind, ip_cidr, reason, source FROM ip_policies
			WHERE source='crowdsec' AND NOT (external_id = ANY($1))`, keepExternalIDs)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var kind, ip, reason, source string
		if err := rows.Scan(&id, &kind, &ip, &reason, &source); err != nil {
			return err
		}
		pid := id
		_ = s.InsertIPPolicyHistory(ctx, models.IPPolicyHistory{
			PolicyID: &pid, Action: "delete", Kind: kind, IPCIDR: ip, Reason: reason, Source: source,
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(keepExternalIDs) == 0 {
		_, err = s.Pool.Exec(ctx, `DELETE FROM ip_policies WHERE source='crowdsec'`)
		if err != nil {
			return err
		}
		return s.ClearSuppressionsNotIn(ctx, nil)
	}
	_, err = s.Pool.Exec(ctx, `
		DELETE FROM ip_policies WHERE source='crowdsec' AND NOT (external_id = ANY($1))`, keepExternalIDs)
	if err != nil {
		return err
	}
	return s.ClearSuppressionsNotIn(ctx, keepExternalIDs)
}

func (s *Store) InsertIPPolicyHistory(ctx context.Context, h models.IPPolicyHistory) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO ip_policy_history (policy_id, action, kind, ip_cidr, reason, source, country_code, actor_email)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		h.PolicyID, h.Action, h.Kind, h.IPCIDR, h.Reason, h.Source, h.CountryCode, h.ActorEmail,
	)
	return err
}

func (s *Store) ListIPPolicyHistory(ctx context.Context, limit, offset int) ([]models.IPPolicyHistory, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, policy_id, action, kind, ip_cidr, reason, source, country_code, actor_email, created_at
		FROM ip_policy_history ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.IPPolicyHistory
	for rows.Next() {
		var h models.IPPolicyHistory
		if err := rows.Scan(&h.ID, &h.PolicyID, &h.Action, &h.Kind, &h.IPCIDR, &h.Reason, &h.Source, &h.CountryCode, &h.ActorEmail, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func scanIPPolicy(row scannable) (models.IPPolicy, error) {
	var p models.IPPolicy
	err := row.Scan(&p.ID, &p.Kind, &p.IPCIDR, &p.Reason, &p.Source, &p.ExternalID, &p.ExpiresAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}
