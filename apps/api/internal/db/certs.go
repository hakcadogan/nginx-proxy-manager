package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nginx-proxy-waf/api/internal/certs"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func (s *Store) CreateCertificate(ctx context.Context, c models.Certificate) (models.Certificate, error) {
	if c.Domains == nil {
		c.Domains = []string{}
	}
	if c.RenewAfterDays == 0 {
		c.RenewAfterDays = 30
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO certificates (
			id, name, domains, kind, acme_challenge, fingerprint_sha256, not_before, not_after,
			issuer, cert_path, key_path, auto_renew, renew_after_days
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING id, name, domains, kind, acme_challenge, fingerprint_sha256, not_before, not_after,
		          issuer, cert_path, key_path, auto_renew, renew_after_days, created_at, updated_at`,
		c.ID, c.Name, c.Domains, c.Kind, c.ACMEChallenge, c.FingerprintSHA256, c.NotBefore, c.NotAfter,
		c.Issuer, c.CertPath, c.KeyPath, c.AutoRenew, c.RenewAfterDays,
	).Scan(
		&c.ID, &c.Name, &c.Domains, &c.Kind, &c.ACMEChallenge, &c.FingerprintSHA256, &c.NotBefore, &c.NotAfter,
		&c.Issuer, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.RenewAfterDays, &c.CreatedAt, &c.UpdatedAt,
	)
	enrichCert(&c, time.Now().UTC())
	return c, err
}

func (s *Store) GetCertificate(ctx context.Context, id uuid.UUID) (models.Certificate, error) {
	var c models.Certificate
	err := s.Pool.QueryRow(ctx, `
		SELECT id, name, domains, kind, acme_challenge, fingerprint_sha256, not_before, not_after,
		       issuer, cert_path, key_path, auto_renew, renew_after_days, created_at, updated_at
		FROM certificates WHERE id=$1`, id,
	).Scan(
		&c.ID, &c.Name, &c.Domains, &c.Kind, &c.ACMEChallenge, &c.FingerprintSHA256, &c.NotBefore, &c.NotAfter,
		&c.Issuer, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.RenewAfterDays, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	enrichCert(&c, time.Now().UTC())
	return c, err
}

func (s *Store) ListCertificates(ctx context.Context) ([]models.Certificate, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, name, domains, kind, acme_challenge, fingerprint_sha256, not_before, not_after,
		       issuer, cert_path, key_path, auto_renew, renew_after_days, created_at, updated_at
		FROM certificates ORDER BY not_after NULLS LAST, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	var out []models.Certificate
	for rows.Next() {
		var c models.Certificate
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Domains, &c.Kind, &c.ACMEChallenge, &c.FingerprintSHA256, &c.NotBefore, &c.NotAfter,
			&c.Issuer, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.RenewAfterDays, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		enrichCert(&c, now)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteCertificate(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM certificates WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateCertificateBundle(ctx context.Context, id uuid.UUID, b *certs.ParsedBundle, certPath, keyPath string) (models.Certificate, error) {
	nb, na := b.NotBefore, b.NotAfter
	_, err := s.Pool.Exec(ctx, `
		UPDATE certificates SET
			fingerprint_sha256=$2, not_before=$3, not_after=$4, issuer=$5,
			cert_path=$6, key_path=$7, domains=$8, updated_at=now()
		WHERE id=$1`,
		id, b.Fingerprint, nb, na, b.Issuer, certPath, keyPath, b.Domains,
	)
	if err != nil {
		return models.Certificate{}, err
	}
	return s.GetCertificate(ctx, id)
}

func (s *Store) ListAutoRenewCertificates(ctx context.Context) ([]models.Certificate, error) {
	all, err := s.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	var out []models.Certificate
	now := time.Now().UTC()
	for _, c := range all {
		if !c.AutoRenew || c.NotAfter == nil {
			continue
		}
		if certs.ShouldRenew(*c.NotAfter, c.RenewAfterDays, now) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *Store) BindHostCertificate(ctx context.Context, hostID, certID uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE proxy_hosts SET certificate_id=$2, updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL`, hostID, certID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func enrichCert(c *models.Certificate, now time.Time) {
	if c.NotAfter == nil {
		return
	}
	d := certs.DaysUntilExpiry(*c.NotAfter, now)
	c.DaysRemaining = &d
	c.ExpiringSoon = d <= c.RenewAfterDays
}

// CertificateIDsInUse returns certificate IDs bound to at least one non-deleted host.
func (s *Store) CertificateIDsInUse(ctx context.Context) (map[uuid.UUID]bool, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT certificate_id FROM proxy_hosts
		WHERE certificate_id IS NOT NULL AND deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *Store) ListUnusedCertificates(ctx context.Context) ([]models.Certificate, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT c.id, c.name, c.domains, c.kind, c.acme_challenge, c.fingerprint_sha256, c.not_before, c.not_after,
		       c.issuer, c.cert_path, c.key_path, c.auto_renew, c.renew_after_days, c.created_at, c.updated_at
		FROM certificates c
		WHERE NOT EXISTS (
			SELECT 1 FROM proxy_hosts h
			WHERE h.certificate_id = c.id AND h.deleted_at IS NULL
		)
		ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	var out []models.Certificate
	for rows.Next() {
		var c models.Certificate
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Domains, &c.Kind, &c.ACMEChallenge, &c.FingerprintSHA256, &c.NotBefore, &c.NotAfter,
			&c.Issuer, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.RenewAfterDays, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		enrichCert(&c, now)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) InsertACMEOperation(ctx context.Context, op models.ACMEOperation) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO acme_operations (certificate_id, operation, challenge, domains, status, error_message, actor_email)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		op.CertificateID, op.Operation, op.Challenge, op.Domains, op.Status, op.ErrorMessage, op.ActorEmail,
	)
	return err
}

func (s *Store) ListACMEOperations(ctx context.Context, limit int) ([]models.ACMEOperation, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, certificate_id, operation, challenge, domains, status, error_message, actor_email, created_at
		FROM acme_operations ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ACMEOperation
	for rows.Next() {
		var o models.ACMEOperation
		if err := rows.Scan(&o.ID, &o.CertificateID, &o.Operation, &o.Challenge, &o.Domains, &o.Status, &o.ErrorMessage, &o.ActorEmail, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
