package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nginx-proxy-waf/api/internal/models"
)

const (
	MaxFailedLogins = 5
	LockoutDuration = 15 * time.Minute
)

const userCols = `id, email, password_hash, role, failed_login_count, locked_until, mfa_secret, mfa_enabled, created_at, updated_at`

func scanUser(row scannable) (models.User, error) {
	var u models.User
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role,
		&u.FailedLoginCount, &u.LockedUntil, &u.MFASecret, &u.MFAEnabled,
		&u.CreatedAt, &u.UpdatedAt,
	)
	return u, err
}

func (s *Store) CreateUser(ctx context.Context, email, hash string, role models.Role) (models.User, error) {
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, role)
		VALUES ($1,$2,$3)
		RETURNING `+userCols,
		strings.ToLower(email), hash, role,
	)
	return scanUser(row)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	row := s.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email=$1`, strings.ToLower(email))
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (models.User, error) {
	row := s.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUserRole(ctx context.Context, id uuid.UUID, role models.Role) (models.User, error) {
	row := s.Pool.QueryRow(ctx, `
		UPDATE users SET role=$2, updated_at=now() WHERE id=$1
		RETURNING `+userCols, id, role)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) UpdateUserPassword(ctx context.Context, id uuid.UUID, hash string) (models.User, error) {
	row := s.Pool.QueryRow(ctx, `
		UPDATE users SET password_hash=$2, failed_login_count=0, locked_until=NULL, updated_at=now()
		WHERE id=$1
		RETURNING `+userCols, id, hash)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n)
	return n, err
}

// DeleteUser removes a user. Caller must enforce last-admin / self-delete rules.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RecordFailedLogin(ctx context.Context, id uuid.UUID) (models.User, error) {
	row := s.Pool.QueryRow(ctx, `
		UPDATE users SET
			failed_login_count = failed_login_count + 1,
			locked_until = CASE
				WHEN failed_login_count + 1 >= $2 THEN now() + ($3::text)::interval
				ELSE locked_until
			END,
			updated_at = now()
		WHERE id=$1
		RETURNING `+userCols, id, MaxFailedLogins, LockoutDuration.String())
	return scanUser(row)
}

func (s *Store) ClearFailedLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE users SET failed_login_count=0, locked_until=NULL, updated_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) UnlockUser(ctx context.Context, id uuid.UUID) (models.User, error) {
	row := s.Pool.QueryRow(ctx, `
		UPDATE users SET failed_login_count=0, locked_until=NULL, updated_at=now() WHERE id=$1
		RETURNING `+userCols, id)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) SetMFASecret(ctx context.Context, id uuid.UUID, secret string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE users SET mfa_secret=$2, mfa_enabled=false, updated_at=now() WHERE id=$1`, id, secret)
	return err
}

func (s *Store) EnableMFA(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE users SET mfa_enabled=true, updated_at=now() WHERE id=$1 AND mfa_secret<>''`, id)
	return err
}

func (s *Store) DisableMFA(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE users SET mfa_enabled=false, mfa_secret='', updated_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) IsLocked(u models.User) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

func HashAPIToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateAPIToken(ctx context.Context, userID uuid.UUID, name, prefix, hash string, scopes []string, expires *time.Time) (models.APIToken, error) {
	if scopes == nil {
		scopes = []string{}
	}
	var t models.APIToken
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, user_id, name, token_prefix, scopes, expires_at, last_used_at, created_at`,
		userID, name, prefix, hash, scopes, expires,
	).Scan(&t.ID, &t.UserID, &t.Name, &t.TokenPrefix, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt)
	return t, err
}

func (s *Store) ListAPITokens(ctx context.Context, userID uuid.UUID) ([]models.APIToken, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, user_id, name, token_prefix, scopes, expires_at, last_used_at, created_at
		FROM api_tokens WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.APIToken
	for rows.Next() {
		var t models.APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenPrefix, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAPIToken(ctx context.Context, userID, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM api_tokens WHERE id=$1 AND user_id=$2`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) LookupAPIToken(ctx context.Context, prefix, hash string) (models.APIToken, models.User, error) {
	var t models.APIToken
	var u models.User
	err := s.Pool.QueryRow(ctx, `
		SELECT t.id, t.user_id, t.name, t.token_prefix, t.scopes, t.expires_at, t.last_used_at, t.created_at,
		       u.id, u.email, u.password_hash, u.role, u.failed_login_count, u.locked_until, u.mfa_secret, u.mfa_enabled, u.created_at, u.updated_at
		FROM api_tokens t JOIN users u ON u.id=t.user_id
		WHERE t.token_prefix=$1 AND t.token_hash=$2`, prefix, hash,
	).Scan(
		&t.ID, &t.UserID, &t.Name, &t.TokenPrefix, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt,
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.FailedLoginCount, &u.LockedUntil, &u.MFASecret, &u.MFAEnabled, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, u, ErrNotFound
	}
	if err != nil {
		return t, u, err
	}
	if t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()) {
		return t, u, ErrNotFound
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE api_tokens SET last_used_at=now() WHERE id=$1`, t.ID)
	return t, u, nil
}

func (s *Store) GetIdempotency(ctx context.Context, userID uuid.UUID, key, method, path string) (status int, body []byte, ok bool, err error) {
	err = s.Pool.QueryRow(ctx, `
		SELECT status_code, response_body FROM idempotency_keys
		WHERE user_id=$1 AND key=$2 AND method=$3 AND path=$4`,
		userID, key, method, path,
	).Scan(&status, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	return status, body, true, nil
}

func (s *Store) SaveIdempotency(ctx context.Context, userID uuid.UUID, key, method, path string, status int, body []byte) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO idempotency_keys (user_id, key, method, path, status_code, response_body)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (user_id, key, method, path) DO NOTHING`,
		userID, key, method, path, status, body)
	return err
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.Pool.QueryRow(ctx, `SELECT value FROM platform_settings WHERE key=$1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO platform_settings (key, value, updated_at) VALUES ($1,$2,now())
		ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()`, key, value)
	return err
}

func (s *Store) RunRetention(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	auditDays := 90
	secDays := 30
	cfgKeep := 50
	if v, err := s.GetSetting(ctx, "audit_retention_days"); err == nil {
		if n, e := parsePositiveInt(v); e == nil {
			auditDays = n
		}
	}
	if v, err := s.GetSetting(ctx, "security_events_retention_days"); err == nil {
		if n, e := parsePositiveInt(v); e == nil {
			secDays = n
		}
	}
	if v, err := s.GetSetting(ctx, "config_versions_retention"); err == nil {
		if n, e := parsePositiveInt(v); e == nil {
			cfgKeep = n
		}
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < now() - make_interval(days => $1)`, auditDays)
	if err != nil {
		return out, err
	}
	out["audit_logs"] = tag.RowsAffected()
	tag, err = s.Pool.Exec(ctx, `DELETE FROM security_events WHERE created_at < now() - make_interval(days => $1)`, secDays)
	if err == nil {
		out["security_events"] = tag.RowsAffected()
	}
	tag, err = s.Pool.Exec(ctx, `
		DELETE FROM config_versions WHERE id NOT IN (
			SELECT id FROM config_versions ORDER BY version DESC LIMIT $1
		)`, cfgKeep)
	if err == nil {
		out["config_versions"] = tag.RowsAffected()
	}
	tag, err = s.Pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours'`)
	if err == nil {
		out["idempotency_keys"] = tag.RowsAffected()
	}
	return out, nil
}

func parsePositiveInt(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not int")
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 {
		return 0, errors.New("not positive")
	}
	return n, nil
}
