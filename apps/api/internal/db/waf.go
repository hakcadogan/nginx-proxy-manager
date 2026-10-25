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
)

const wafPolicyCols = `
id, name, scope, host_id, enabled, engine_mode, paranoia_level, audit_relevant_only,
COALESCE(inbound_anomaly_score_threshold, 5),
COALESCE(outbound_anomaly_score_threshold, 4),
created_at, updated_at`

const wafExceptionCols = `
id, policy_id, host_id, rule_id, path_prefix, argument, reason, enabled, created_by, created_at, updated_at`

func (s *Store) GetGlobalWAFPolicy(ctx context.Context) (models.WAFPolicy, error) {
	row := s.Pool.QueryRow(ctx, `SELECT `+wafPolicyCols+` FROM waf_policies WHERE scope='global' LIMIT 1`)
	return scanWAFPolicy(row)
}

func (s *Store) GetHostWAFPolicy(ctx context.Context, hostID uuid.UUID) (models.WAFPolicy, error) {
	row := s.Pool.QueryRow(ctx, `SELECT `+wafPolicyCols+` FROM waf_policies WHERE scope='host' AND host_id=$1`, hostID)
	p, err := scanWAFPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) ListWAFPolicies(ctx context.Context) ([]models.WAFPolicy, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+wafPolicyCols+` FROM waf_policies ORDER BY scope, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WAFPolicy
	for rows.Next() {
		p, err := scanWAFPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetWAFPolicy(ctx context.Context, id uuid.UUID) (models.WAFPolicy, error) {
	row := s.Pool.QueryRow(ctx, `SELECT `+wafPolicyCols+` FROM waf_policies WHERE id=$1`, id)
	p, err := scanWAFPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) UpdateWAFPolicy(ctx context.Context, p models.WAFPolicy) (models.WAFPolicy, error) {
	if p.InboundAnomalyScoreThreshold == 0 {
		p.InboundAnomalyScoreThreshold = 5
	}
	if p.OutboundAnomalyScoreThreshold == 0 {
		p.OutboundAnomalyScoreThreshold = 4
	}
	err := s.Pool.QueryRow(ctx, `
		UPDATE waf_policies SET
			name=$2, enabled=$3, engine_mode=$4, paranoia_level=$5, audit_relevant_only=$6,
			inbound_anomaly_score_threshold=$7, outbound_anomaly_score_threshold=$8, updated_at=now()
		WHERE id=$1
		RETURNING `+wafPolicyCols,
		p.ID, p.Name, p.Enabled, p.EngineMode, p.ParanoiaLevel, p.AuditRelevantOnly,
		p.InboundAnomalyScoreThreshold, p.OutboundAnomalyScoreThreshold,
	).Scan(
		&p.ID, &p.Name, &p.Scope, &p.HostID, &p.Enabled, &p.EngineMode, &p.ParanoiaLevel, &p.AuditRelevantOnly,
		&p.InboundAnomalyScoreThreshold, &p.OutboundAnomalyScoreThreshold, &p.CreatedAt, &p.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) UpsertHostWAFPolicy(ctx context.Context, hostID uuid.UUID, p models.WAFPolicy) (models.WAFPolicy, error) {
	existing, err := s.GetHostWAFPolicy(ctx, hostID)
	if err == nil {
		p.ID = existing.ID
		p.Name = existing.Name
		return s.UpdateWAFPolicy(ctx, p)
	}
	if !errors.Is(err, ErrNotFound) {
		return p, err
	}
	if p.Name == "" {
		p.Name = "host-policy"
	}
	if p.InboundAnomalyScoreThreshold == 0 {
		p.InboundAnomalyScoreThreshold = 5
	}
	if p.OutboundAnomalyScoreThreshold == 0 {
		p.OutboundAnomalyScoreThreshold = 4
	}
	if p.ParanoiaLevel == 0 {
		p.ParanoiaLevel = 1
	}
	if p.EngineMode == "" {
		p.EngineMode = "DetectionOnly"
	}
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO waf_policies (name, scope, host_id, enabled, engine_mode, paranoia_level, audit_relevant_only,
			inbound_anomaly_score_threshold, outbound_anomaly_score_threshold)
		VALUES ($1,'host',$2,$3,$4,$5,$6,$7,$8)
		RETURNING `+wafPolicyCols,
		p.Name, hostID, p.Enabled, p.EngineMode, p.ParanoiaLevel, p.AuditRelevantOnly,
		p.InboundAnomalyScoreThreshold, p.OutboundAnomalyScoreThreshold,
	).Scan(
		&p.ID, &p.Name, &p.Scope, &p.HostID, &p.Enabled, &p.EngineMode, &p.ParanoiaLevel, &p.AuditRelevantOnly,
		&p.InboundAnomalyScoreThreshold, &p.OutboundAnomalyScoreThreshold, &p.CreatedAt, &p.UpdatedAt,
	)
	return p, err
}

func (s *Store) ListWAFExceptions(ctx context.Context, policyID *uuid.UUID) ([]models.WAFException, error) {
	var rows pgx.Rows
	var err error
	if policyID != nil {
		rows, err = s.Pool.Query(ctx, `
			SELECT `+wafExceptionCols+` FROM waf_exceptions WHERE policy_id=$1 ORDER BY created_at DESC`, *policyID)
	} else {
		rows, err = s.Pool.Query(ctx, `
			SELECT `+wafExceptionCols+` FROM waf_exceptions ORDER BY created_at DESC LIMIT 500`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WAFException
	for rows.Next() {
		e, err := scanWAFException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CreateWAFException(ctx context.Context, e models.WAFException) (models.WAFException, error) {
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO waf_exceptions (policy_id, host_id, rule_id, path_prefix, argument, reason, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING `+wafExceptionCols,
		e.PolicyID, e.HostID, e.RuleID, e.PathPrefix, e.Argument, e.Reason, e.Enabled, e.CreatedBy,
	).Scan(&e.ID, &e.PolicyID, &e.HostID, &e.RuleID, &e.PathPrefix, &e.Argument, &e.Reason, &e.Enabled, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

func (s *Store) GetWAFException(ctx context.Context, id uuid.UUID) (models.WAFException, error) {
	var e models.WAFException
	err := s.Pool.QueryRow(ctx, `SELECT `+wafExceptionCols+` FROM waf_exceptions WHERE id=$1`, id).
		Scan(&e.ID, &e.PolicyID, &e.HostID, &e.RuleID, &e.PathPrefix, &e.Argument, &e.Reason, &e.Enabled, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

func (s *Store) UpdateWAFException(ctx context.Context, e models.WAFException) (models.WAFException, error) {
	err := s.Pool.QueryRow(ctx, `
		UPDATE waf_exceptions SET
			host_id=$2, rule_id=$3, path_prefix=$4, argument=$5, reason=$6, enabled=$7, updated_at=now()
		WHERE id=$1
		RETURNING `+wafExceptionCols,
		e.ID, e.HostID, e.RuleID, e.PathPrefix, e.Argument, e.Reason, e.Enabled,
	).Scan(&e.ID, &e.PolicyID, &e.HostID, &e.RuleID, &e.PathPrefix, &e.Argument, &e.Reason, &e.Enabled, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

func (s *Store) DeleteWAFException(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM waf_exceptions WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListSecurityEvents(ctx context.Context, limit, offset int) ([]models.SecurityEvent, error) {
	return s.SearchSecurityEvents(ctx, SecurityEventFilter{Limit: limit, Offset: offset})
}

type SecurityEventFilter struct {
	Source string
	Q      string
	RuleID string
	Domain string
	Limit  int
	Offset int
}

func (s *Store) SearchSecurityEvents(ctx context.Context, f SecurityEventFilter) ([]models.SecurityEvent, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{"1=1"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.Source != "" {
		add("source=$%d", f.Source)
	}
	if f.RuleID != "" {
		add("rule_id=$%d", f.RuleID)
	}
	if f.Domain != "" {
		add("LOWER(domain) LIKE $%d", "%"+strings.ToLower(f.Domain)+"%")
	}
	if f.Q != "" {
		q := "%" + strings.ToLower(f.Q) + "%"
		args = append(args, q, q, q)
		n := len(args)
		where = append(where, fmt.Sprintf(
			`(LOWER(message) LIKE $%d OR LOWER(uri) LIKE $%d OR LOWER(payload_summary) LIKE $%d)`,
			n-2, n-1, n))
	}
	args = append(args, f.Limit, f.Offset)
	limIdx, offIdx := len(args)-1, len(args)
	sql := fmt.Sprintf(`
		SELECT id, source, host_id, domain, rule_id, severity, message, uri, method, client_ip, payload_summary, unique_id, created_at
		FROM security_events WHERE %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		strings.Join(where, " AND "), limIdx, offIdx)
	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SecurityEvent
	for rows.Next() {
		ev, err := scanSecurityEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

type RuleEventCount struct {
	RuleID       string
	Count        int
	LastClientIP string
	LastSeen     time.Time
}

func (s *Store) AggregateSecurityEventsByRule(ctx context.Context, source string, limit int) ([]RuleEventCount, error) {
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	if source == "" {
		source = "waf"
	}
	// Last IP/time = most recent event for that rule (REQ-WAF-014).
	rows, err := s.Pool.Query(ctx, `
		SELECT rule_id,
		       COUNT(*)::int AS c,
		       COALESCE((ARRAY_AGG(client_ip ORDER BY created_at DESC))[1], '') AS last_ip,
		       MAX(created_at) AS last_seen
		FROM security_events WHERE source=$1 AND rule_id <> ''
		GROUP BY rule_id ORDER BY c DESC LIMIT $2`, source, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleEventCount
	for rows.Next() {
		var r RuleEventCount
		if err := rows.Scan(&r.RuleID, &r.Count, &r.LastClientIP, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetSecurityEvent(ctx context.Context, id int64) (models.SecurityEvent, error) {
	row := s.Pool.QueryRow(ctx, `
		SELECT id, source, host_id, domain, rule_id, severity, message, uri, method, client_ip, payload_summary, unique_id, created_at
		FROM security_events WHERE id=$1`, id)
	ev, err := scanSecurityEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ev, ErrNotFound
	}
	return ev, err
}

func (s *Store) InsertSecurityEvent(ctx context.Context, ev models.SecurityEvent) (models.SecurityEvent, error) {
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO security_events (source, host_id, domain, rule_id, severity, message, uri, method, client_ip, payload_summary, unique_id)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
		WHERE $11 = '' OR NOT EXISTS (
			SELECT 1 FROM security_events WHERE unique_id = $11 AND unique_id <> ''
		)
		RETURNING id, source, host_id, domain, rule_id, severity, message, uri, method, client_ip, payload_summary, unique_id, created_at`,
		ev.Source, ev.HostID, ev.Domain, ev.RuleID, ev.Severity, ev.Message, ev.URI, ev.Method, ev.ClientIP, ev.PayloadSummary, ev.UniqueID,
	).Scan(&ev.ID, &ev.Source, &ev.HostID, &ev.Domain, &ev.RuleID, &ev.Severity, &ev.Message, &ev.URI, &ev.Method, &ev.ClientIP, &ev.PayloadSummary, &ev.UniqueID, &ev.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ev, nil
	}
	return ev, err
}

func scanWAFPolicy(row scannable) (models.WAFPolicy, error) {
	var p models.WAFPolicy
	err := row.Scan(
		&p.ID, &p.Name, &p.Scope, &p.HostID, &p.Enabled, &p.EngineMode, &p.ParanoiaLevel, &p.AuditRelevantOnly,
		&p.InboundAnomalyScoreThreshold, &p.OutboundAnomalyScoreThreshold, &p.CreatedAt, &p.UpdatedAt,
	)
	return p, err
}

func scanWAFException(row scannable) (models.WAFException, error) {
	var e models.WAFException
	err := row.Scan(&e.ID, &e.PolicyID, &e.HostID, &e.RuleID, &e.PathPrefix, &e.Argument, &e.Reason, &e.Enabled, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

func scanSecurityEvent(row scannable) (models.SecurityEvent, error) {
	var ev models.SecurityEvent
	err := row.Scan(&ev.ID, &ev.Source, &ev.HostID, &ev.Domain, &ev.RuleID, &ev.Severity, &ev.Message, &ev.URI, &ev.Method, &ev.ClientIP, &ev.PayloadSummary, &ev.UniqueID, &ev.CreatedAt)
	return ev, err
}
