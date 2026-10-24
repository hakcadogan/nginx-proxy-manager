package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nginx-proxy-waf/api/internal/models"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	Pool *pgxpool.Pool
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) ListRateProfiles(ctx context.Context) ([]models.RateLimitProfile, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, name, requests_per_second, burst, connections_per_ip,
		       COALESCE(retry_after_seconds, 1), created_at
		FROM rate_limit_profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.RateLimitProfile
	for rows.Next() {
		var p models.RateLimitProfile
		if err := rows.Scan(&p.ID, &p.Name, &p.RequestsPerSecond, &p.Burst, &p.ConnectionsPerIP,
			&p.RetryAfterSeconds, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetRateProfile(ctx context.Context, id uuid.UUID) (models.RateLimitProfile, error) {
	var p models.RateLimitProfile
	err := s.Pool.QueryRow(ctx, `
		SELECT id, name, requests_per_second, burst, connections_per_ip,
		       COALESCE(retry_after_seconds, 1), created_at
		FROM rate_limit_profiles WHERE id=$1`, id,
	).Scan(&p.ID, &p.Name, &p.RequestsPerSecond, &p.Burst, &p.ConnectionsPerIP,
		&p.RetryAfterSeconds, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) CreateRateProfile(ctx context.Context, p models.RateLimitProfile) (models.RateLimitProfile, error) {
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO rate_limit_profiles (name, requests_per_second, burst, connections_per_ip, retry_after_seconds)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, name, requests_per_second, burst, connections_per_ip, retry_after_seconds, created_at`,
		p.Name, p.RequestsPerSecond, p.Burst, p.ConnectionsPerIP, p.RetryAfterSeconds,
	).Scan(&p.ID, &p.Name, &p.RequestsPerSecond, &p.Burst, &p.ConnectionsPerIP,
		&p.RetryAfterSeconds, &p.CreatedAt)
	return p, err
}

func (s *Store) UpdateRateProfile(ctx context.Context, p models.RateLimitProfile) (models.RateLimitProfile, error) {
	err := s.Pool.QueryRow(ctx, `
		UPDATE rate_limit_profiles SET name=$2, requests_per_second=$3, burst=$4, connections_per_ip=$5,
		                            retry_after_seconds=$6
		WHERE id=$1
		RETURNING id, name, requests_per_second, burst, connections_per_ip, retry_after_seconds, created_at`,
		p.ID, p.Name, p.RequestsPerSecond, p.Burst, p.ConnectionsPerIP, p.RetryAfterSeconds,
	).Scan(&p.ID, &p.Name, &p.RequestsPerSecond, &p.Burst, &p.ConnectionsPerIP,
		&p.RetryAfterSeconds, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) DeleteRateProfile(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM rate_limit_profiles WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) NextConfigVersion(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM config_versions`).Scan(&n)
	return n, err
}

func (s *Store) SaveConfigVersion(ctx context.Context, v models.ConfigVersion) (models.ConfigVersion, error) {
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO config_versions (version, checksum, rendered, status, message, created_by)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, version, checksum, rendered, status, message, created_by, created_at`,
		v.Version, v.Checksum, v.Rendered, v.Status, v.Message, v.CreatedBy,
	).Scan(&v.ID, &v.Version, &v.Checksum, &v.Rendered, &v.Status, &v.Message, &v.CreatedBy, &v.CreatedAt)
	return v, err
}

func (s *Store) UpdateConfigVersionStatus(ctx context.Context, id uuid.UUID, status, message string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE config_versions SET status=$2, message=$3 WHERE id=$1`, id, status, message)
	return err
}

func (s *Store) ListConfigVersions(ctx context.Context, limit int) ([]models.ConfigVersion, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, version, checksum, status, message, created_by, created_at
		FROM config_versions ORDER BY version DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ConfigVersion
	for rows.Next() {
		var v models.ConfigVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.Checksum, &v.Status, &v.Message, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetConfigVersion(ctx context.Context, id uuid.UUID) (models.ConfigVersion, error) {
	var v models.ConfigVersion
	err := s.Pool.QueryRow(ctx, `
		SELECT id, version, checksum, rendered, status, message, created_by, created_at
		FROM config_versions WHERE id=$1`, id,
	).Scan(&v.ID, &v.Version, &v.Checksum, &v.Rendered, &v.Status, &v.Message, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}

func (s *Store) LatestAppliedConfig(ctx context.Context) (models.ConfigVersion, error) {
	var v models.ConfigVersion
	err := s.Pool.QueryRow(ctx, `
		SELECT id, version, checksum, rendered, status, message, created_by, created_at
		FROM config_versions WHERE status='applied' ORDER BY version DESC LIMIT 1`,
	).Scan(&v.ID, &v.Version, &v.Checksum, &v.Rendered, &v.Status, &v.Message, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}

func (s *Store) InsertAudit(ctx context.Context, a models.AuditLog) error {
	if a.Details == nil {
		a.Details = json.RawMessage(`{}`)
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_logs (actor_user_id, actor_email, action, resource_type, resource_id, request_id, ip, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.ActorUserID, a.ActorEmail, a.Action, a.ResourceType, a.ResourceID, a.RequestID, a.IP, a.Details,
	)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit, offset int) ([]models.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, actor_user_id, actor_email, action, resource_type, resource_id, request_id, ip, details, created_at
		FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuditLog
	for rows.Next() {
		var a models.AuditLog
		if err := rows.Scan(&a.ID, &a.ActorUserID, &a.ActorEmail, &a.Action, &a.ResourceType, &a.ResourceID, &a.RequestID, &a.IP, &a.Details, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Ensure compile-time use of time in case of future fields.
var _ = time.Now
