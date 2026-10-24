package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nginx-proxy-waf/api/internal/models"
)

const upstreamSelectCols = `
id, name, algorithm, hash_key, scheme, sni,
connect_timeout, send_timeout, read_timeout,
max_fails, fail_timeout,
health_check_enabled, health_check_path, health_check_interval_sec,
COALESCE(next_upstream, 'error timeout http_502 http_503 http_504'),
COALESCE(next_upstream_tries, 0),
COALESCE(next_upstream_timeout, '0'),
created_at, updated_at`

func (s *Store) ListUpstreams(ctx context.Context) ([]models.Upstream, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT `+upstreamSelectCols+`
		FROM upstreams ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Upstream
	for rows.Next() {
		u, err := scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		members, err := s.ListMembers(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Members = members
	}
	return out, nil
}

func (s *Store) GetUpstream(ctx context.Context, id uuid.UUID) (models.Upstream, error) {
	row := s.Pool.QueryRow(ctx, `
		SELECT `+upstreamSelectCols+`
		FROM upstreams WHERE id=$1`, id)
	u, err := scanUpstream(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	members, err := s.ListMembers(ctx, id)
	if err != nil {
		return u, err
	}
	u.Members = members
	return u, nil
}

func (s *Store) CreateUpstream(ctx context.Context, u models.Upstream) (models.Upstream, error) {
	normalizeUpstream(&u)
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO upstreams (
			name, algorithm, hash_key, scheme, sni,
			connect_timeout, send_timeout, read_timeout,
			max_fails, fail_timeout,
			health_check_enabled, health_check_path, health_check_interval_sec,
			next_upstream, next_upstream_tries, next_upstream_timeout
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING `+upstreamSelectCols,
		u.Name, u.Algorithm, u.HashKey, u.Scheme, u.SNI,
		u.ConnectTimeout, u.SendTimeout, u.ReadTimeout,
		u.MaxFails, u.FailTimeout,
		u.HealthCheckEnabled, u.HealthCheckPath, u.HealthCheckIntervalSec,
		u.NextUpstream, u.NextUpstreamTries, u.NextUpstreamTimeout,
	).Scan(
		&u.ID, &u.Name, &u.Algorithm, &u.HashKey, &u.Scheme, &u.SNI,
		&u.ConnectTimeout, &u.SendTimeout, &u.ReadTimeout,
		&u.MaxFails, &u.FailTimeout,
		&u.HealthCheckEnabled, &u.HealthCheckPath, &u.HealthCheckIntervalSec,
		&u.NextUpstream, &u.NextUpstreamTries, &u.NextUpstreamTimeout,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return u, err
	}
	u.Members = []models.UpstreamMember{}
	return u, nil
}

func (s *Store) UpdateUpstream(ctx context.Context, u models.Upstream) (models.Upstream, error) {
	normalizeUpstream(&u)
	err := s.Pool.QueryRow(ctx, `
		UPDATE upstreams SET
			name=$2, algorithm=$3, hash_key=$4, scheme=$5, sni=$6,
			connect_timeout=$7, send_timeout=$8, read_timeout=$9,
			max_fails=$10, fail_timeout=$11,
			health_check_enabled=$12, health_check_path=$13, health_check_interval_sec=$14,
			next_upstream=$15, next_upstream_tries=$16, next_upstream_timeout=$17,
			updated_at=now()
		WHERE id=$1
		RETURNING `+upstreamSelectCols,
		u.ID, u.Name, u.Algorithm, u.HashKey, u.Scheme, u.SNI,
		u.ConnectTimeout, u.SendTimeout, u.ReadTimeout,
		u.MaxFails, u.FailTimeout,
		u.HealthCheckEnabled, u.HealthCheckPath, u.HealthCheckIntervalSec,
		u.NextUpstream, u.NextUpstreamTries, u.NextUpstreamTimeout,
	).Scan(
		&u.ID, &u.Name, &u.Algorithm, &u.HashKey, &u.Scheme, &u.SNI,
		&u.ConnectTimeout, &u.SendTimeout, &u.ReadTimeout,
		&u.MaxFails, &u.FailTimeout,
		&u.HealthCheckEnabled, &u.HealthCheckPath, &u.HealthCheckIntervalSec,
		&u.NextUpstream, &u.NextUpstreamTries, &u.NextUpstreamTimeout,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	members, err := s.ListMembers(ctx, u.ID)
	if err != nil {
		return u, err
	}
	u.Members = members
	return u, nil
}

func (s *Store) DeleteUpstream(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM upstreams WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListMembers(ctx context.Context, upstreamID uuid.UUID) ([]models.UpstreamMember, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, upstream_id, host, port, weight, COALESCE(max_conns,0), is_backup, is_down, is_drain,
		       COALESCE(admin_disabled,false), last_check_at, last_check_ok, created_at, updated_at
		FROM upstream_members WHERE upstream_id=$1
		ORDER BY host, port`, upstreamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.UpstreamMember
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) GetMember(ctx context.Context, upstreamID, memberID uuid.UUID) (models.UpstreamMember, error) {
	row := s.Pool.QueryRow(ctx, `
		SELECT id, upstream_id, host, port, weight, COALESCE(max_conns,0), is_backup, is_down, is_drain,
		       COALESCE(admin_disabled,false), last_check_at, last_check_ok, created_at, updated_at
		FROM upstream_members WHERE id=$1 AND upstream_id=$2`, memberID, upstreamID)
	m, err := scanMember(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

func (s *Store) CreateMember(ctx context.Context, m models.UpstreamMember) (models.UpstreamMember, error) {
	if m.Weight < 1 {
		m.Weight = 1
	}
	if m.MaxConns < 0 {
		m.MaxConns = 0
	}
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO upstream_members (
			upstream_id, host, port, weight, max_conns, is_backup, is_down, is_drain, admin_disabled
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, upstream_id, host, port, weight, max_conns, is_backup, is_down, is_drain,
		          admin_disabled, last_check_at, last_check_ok, created_at, updated_at`,
		m.UpstreamID, m.Host, m.Port, m.Weight, m.MaxConns, m.IsBackup, m.IsDown, m.IsDrain, m.AdminDisabled,
	).Scan(
		&m.ID, &m.UpstreamID, &m.Host, &m.Port, &m.Weight, &m.MaxConns, &m.IsBackup, &m.IsDown, &m.IsDrain,
		&m.AdminDisabled, &m.LastCheckAt, &m.LastCheckOK, &m.CreatedAt, &m.UpdatedAt,
	)
	return m, err
}

func (s *Store) UpdateMember(ctx context.Context, m models.UpstreamMember) (models.UpstreamMember, error) {
	if m.Weight < 1 {
		m.Weight = 1
	}
	if m.MaxConns < 0 {
		m.MaxConns = 0
	}
	err := s.Pool.QueryRow(ctx, `
		UPDATE upstream_members SET
			host=$3, port=$4, weight=$5, max_conns=$6, is_backup=$7, is_down=$8, is_drain=$9,
			admin_disabled=$10, updated_at=now()
		WHERE id=$1 AND upstream_id=$2
		RETURNING id, upstream_id, host, port, weight, max_conns, is_backup, is_down, is_drain,
		          admin_disabled, last_check_at, last_check_ok, created_at, updated_at`,
		m.ID, m.UpstreamID, m.Host, m.Port, m.Weight, m.MaxConns, m.IsBackup, m.IsDown, m.IsDrain, m.AdminDisabled,
	).Scan(
		&m.ID, &m.UpstreamID, &m.Host, &m.Port, &m.Weight, &m.MaxConns, &m.IsBackup, &m.IsDown, &m.IsDrain,
		&m.AdminDisabled, &m.LastCheckAt, &m.LastCheckOK, &m.CreatedAt, &m.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

func (s *Store) DeleteMember(ctx context.Context, upstreamID, memberID uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM upstream_members WHERE id=$1 AND upstream_id=$2`, memberID, upstreamID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetMemberHealth updates probe results; toggles is_down unless drain or admin-disabled (REQ-LB-008/011).
func (s *Store) SetMemberHealth(ctx context.Context, memberID uuid.UUID, ok bool) (changed bool, err error) {
	var isDrain, wasDown, adminDisabled bool
	err = s.Pool.QueryRow(ctx, `
		SELECT is_drain, is_down, COALESCE(admin_disabled,false)
		FROM upstream_members WHERE id=$1`, memberID,
	).Scan(&isDrain, &wasDown, &adminDisabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	newDown := wasDown
	switch {
	case isDrain:
		newDown = true
	case adminDisabled:
		// Manual disable sticks until operator re-enables; probe only records last_check_*.
		newDown = true
	default:
		newDown = !ok
	}
	changed = newDown != wasDown
	now := time.Now().UTC()
	_, err = s.Pool.Exec(ctx, `
		UPDATE upstream_members SET
			last_check_at=$2, last_check_ok=$3, is_down=$4, updated_at=now()
		WHERE id=$1`, memberID, now, ok, newDown)
	return changed, err
}

func (s *Store) ListHealthCheckUpstreams(ctx context.Context) ([]models.Upstream, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT `+upstreamSelectCols+`
		FROM upstreams WHERE health_check_enabled=true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Upstream
	for rows.Next() {
		u, err := scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		members, err := s.ListMembers(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		u.Members = members
		out = append(out, u)
	}
	return out, rows.Err()
}

func normalizeUpstream(u *models.Upstream) {
	if u.Algorithm == "" {
		u.Algorithm = "round_robin"
	}
	if u.HashKey == "" {
		u.HashKey = "$request_uri"
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.ConnectTimeout == "" {
		u.ConnectTimeout = "5s"
	}
	if u.SendTimeout == "" {
		u.SendTimeout = "60s"
	}
	if u.ReadTimeout == "" {
		u.ReadTimeout = "60s"
	}
	if u.FailTimeout == "" {
		u.FailTimeout = "10s"
	}
	if u.MaxFails == 0 {
		u.MaxFails = 3
	}
	if u.HealthCheckPath == "" {
		u.HealthCheckPath = "/"
	}
	if u.HealthCheckIntervalSec < 5 {
		u.HealthCheckIntervalSec = 10
	}
	if u.NextUpstream == "" {
		u.NextUpstream = "error timeout http_502 http_503 http_504"
	}
	if u.NextUpstreamTimeout == "" {
		u.NextUpstreamTimeout = "0"
	}
}

func scanUpstream(row scannable) (models.Upstream, error) {
	var u models.Upstream
	err := row.Scan(
		&u.ID, &u.Name, &u.Algorithm, &u.HashKey, &u.Scheme, &u.SNI,
		&u.ConnectTimeout, &u.SendTimeout, &u.ReadTimeout,
		&u.MaxFails, &u.FailTimeout,
		&u.HealthCheckEnabled, &u.HealthCheckPath, &u.HealthCheckIntervalSec,
		&u.NextUpstream, &u.NextUpstreamTries, &u.NextUpstreamTimeout,
		&u.CreatedAt, &u.UpdatedAt,
	)
	return u, err
}

func scanMember(row scannable) (models.UpstreamMember, error) {
	var m models.UpstreamMember
	err := row.Scan(
		&m.ID, &m.UpstreamID, &m.Host, &m.Port, &m.Weight, &m.MaxConns, &m.IsBackup, &m.IsDown, &m.IsDrain,
		&m.AdminDisabled, &m.LastCheckAt, &m.LastCheckOK, &m.CreatedAt, &m.UpdatedAt,
	)
	return m, err
}
