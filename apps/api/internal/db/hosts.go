package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nginx-proxy-waf/api/internal/models"
)

const hostSelectCols = `
id, primary_domain, aliases, upstream_scheme, upstream_host, upstream_port,
path_prefix, enabled, force_https, websocket_support, access_log_enabled,
COALESCE(access_log_format,'main'),
COALESCE(error_log_enabled,true),
custom_headers, locations, rate_limit_profile_id, certificate_id, upstream_id, waf_enabled,
COALESCE(security_headers_preset,'none'),
COALESCE(listen_http,true), COALESCE(listen_https,true), COALESCE(http2,true),
COALESCE(client_max_body_size,'10m'),
COALESCE(connect_timeout,'5s'), COALESCE(send_timeout,'60s'), COALESCE(read_timeout,'60s'),
COALESCE(proxy_protocol,'http'),
COALESCE(allowed_methods,'[]'::jsonb),
created_at, updated_at`

type scannable interface {
	Scan(dest ...any) error
}

func applyHostDefaults(h *models.ProxyHost) {
	if h.Aliases == nil {
		h.Aliases = []string{}
	}
	if h.SecurityHeadersPreset == "" {
		h.SecurityHeadersPreset = "none"
	}
	if h.ClientMaxBodySize == "" {
		h.ClientMaxBodySize = "10m"
	}
	if h.ConnectTimeout == "" {
		h.ConnectTimeout = "5s"
	}
	if h.SendTimeout == "" {
		h.SendTimeout = "60s"
	}
	if h.ReadTimeout == "" {
		h.ReadTimeout = "60s"
	}
	if h.ProxyProtocol == "" {
		h.ProxyProtocol = "http"
	}
	if h.AccessLogFormat == "" {
		h.AccessLogFormat = "main"
	}
	// Zero-value bools for create: default listen both + http2 on unless explicitly set via JSON
}

func scanHost(row scannable) (models.ProxyHost, error) {
	var h models.ProxyHost
	var headers, locs, methods []byte
	err := row.Scan(
		&h.ID, &h.PrimaryDomain, &h.Aliases, &h.UpstreamScheme, &h.UpstreamHost, &h.UpstreamPort,
		&h.PathPrefix, &h.Enabled, &h.ForceHTTPS, &h.WebsocketSupport, &h.AccessLogEnabled,
		&h.AccessLogFormat, &h.ErrorLogEnabled,
		&headers, &locs, &h.RateLimitProfileID, &h.CertificateID, &h.UpstreamID, &h.WAFEnabled,
		&h.SecurityHeadersPreset,
		&h.ListenHTTP, &h.ListenHTTPS, &h.HTTP2, &h.ClientMaxBodySize,
		&h.ConnectTimeout, &h.SendTimeout, &h.ReadTimeout, &h.ProxyProtocol,
		&methods,
		&h.CreatedAt, &h.UpdatedAt,
	)
	if err != nil {
		return h, err
	}
	if len(headers) > 0 {
		_ = json.Unmarshal(headers, &h.CustomHeaders)
	}
	if len(locs) > 0 {
		_ = json.Unmarshal(locs, &h.Locations)
	}
	if len(methods) > 0 {
		_ = json.Unmarshal(methods, &h.AllowedMethods)
	}
	if h.Aliases == nil {
		h.Aliases = []string{}
	}
	if h.CustomHeaders == nil {
		h.CustomHeaders = []models.HeaderRule{}
	}
	if h.Locations == nil {
		h.Locations = []models.LocationRule{}
	}
	if h.AllowedMethods == nil {
		h.AllowedMethods = []string{}
	}
	applyHostDefaults(&h)
	return h, nil
}

func (s *Store) ListHosts(ctx context.Context, q string, limit, offset int) ([]models.ProxyHost, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	args := []any{}
	where := `deleted_at IS NULL`
	if q != "" {
		args = append(args, "%"+strings.ToLower(q)+"%")
		where += fmt.Sprintf(` AND (LOWER(primary_domain) LIKE $%d OR EXISTS (
			SELECT 1 FROM unnest(aliases) a WHERE LOWER(a) LIKE $%d))`, len(args), len(args))
	}
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM proxy_hosts WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	args = append(args, limit, offset)
	rows, err := s.Pool.Query(ctx, fmt.Sprintf(`
		SELECT `+hostSelectCols+`
		FROM proxy_hosts WHERE %s
		ORDER BY primary_domain ASC
		LIMIT $%d OFFSET $%d`, where, limitIdx, offsetIdx), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.ProxyHost
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

func (s *Store) GetHost(ctx context.Context, id uuid.UUID) (models.ProxyHost, error) {
	row := s.Pool.QueryRow(ctx, `SELECT `+hostSelectCols+` FROM proxy_hosts WHERE id=$1 AND deleted_at IS NULL`, id)
	h, err := scanHost(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, ErrNotFound
	}
	return h, err
}

// FindHostIDByDomain matches primary_domain or aliases (case-insensitive).
func (s *Store) FindHostIDByDomain(ctx context.Context, domain string) (uuid.UUID, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return uuid.Nil, ErrNotFound
	}
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		SELECT id FROM proxy_hosts
		WHERE deleted_at IS NULL
		  AND (LOWER(primary_domain)=$1 OR EXISTS (
		        SELECT 1 FROM unnest(aliases) a WHERE LOWER(a)=$1))
		LIMIT 1`, d).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return id, err
}

func (s *Store) CreateHost(ctx context.Context, h models.ProxyHost) (models.ProxyHost, error) {
	headers, _ := json.Marshal(h.CustomHeaders)
	locs, _ := json.Marshal(h.Locations)
	applyHostDefaults(&h)
	// Default listen flags when omitted from JSON (false zero-value): enable both.
	// Callers should set explicitly; handlers set defaults before Create.
	methods, _ := json.Marshal(h.AllowedMethods)
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO proxy_hosts (
			primary_domain, aliases, upstream_scheme, upstream_host, upstream_port,
			path_prefix, enabled, force_https, websocket_support, access_log_enabled, access_log_format,
			error_log_enabled,
			custom_headers, locations, rate_limit_profile_id, certificate_id, upstream_id, waf_enabled,
			security_headers_preset, listen_http, listen_https, http2, client_max_body_size,
			connect_timeout, send_timeout, read_timeout, proxy_protocol, allowed_methods
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
		RETURNING `+hostSelectCols,
		h.PrimaryDomain, h.Aliases, h.UpstreamScheme, h.UpstreamHost, h.UpstreamPort,
		h.PathPrefix, h.Enabled, h.ForceHTTPS, h.WebsocketSupport, h.AccessLogEnabled, h.AccessLogFormat,
		h.ErrorLogEnabled,
		headers, locs, h.RateLimitProfileID, h.CertificateID, h.UpstreamID, h.WAFEnabled, h.SecurityHeadersPreset,
		h.ListenHTTP, h.ListenHTTPS, h.HTTP2, h.ClientMaxBodySize,
		h.ConnectTimeout, h.SendTimeout, h.ReadTimeout, h.ProxyProtocol, methods,
	)
	return scanHost(row)
}

func (s *Store) UpdateHost(ctx context.Context, h models.ProxyHost) (models.ProxyHost, error) {
	headers, _ := json.Marshal(h.CustomHeaders)
	locs, _ := json.Marshal(h.Locations)
	applyHostDefaults(&h)
	methods, _ := json.Marshal(h.AllowedMethods)
	row := s.Pool.QueryRow(ctx, `
		UPDATE proxy_hosts SET
			primary_domain=$2, aliases=$3, upstream_scheme=$4, upstream_host=$5, upstream_port=$6,
			path_prefix=$7, enabled=$8, force_https=$9, websocket_support=$10, access_log_enabled=$11, access_log_format=$12,
			error_log_enabled=$13,
			custom_headers=$14, locations=$15, rate_limit_profile_id=$16, certificate_id=$17, upstream_id=$18, waf_enabled=$19,
			security_headers_preset=$20, listen_http=$21, listen_https=$22, http2=$23, client_max_body_size=$24,
			connect_timeout=$25, send_timeout=$26, read_timeout=$27, proxy_protocol=$28, allowed_methods=$29, updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL
		RETURNING `+hostSelectCols,
		h.ID, h.PrimaryDomain, h.Aliases, h.UpstreamScheme, h.UpstreamHost, h.UpstreamPort,
		h.PathPrefix, h.Enabled, h.ForceHTTPS, h.WebsocketSupport, h.AccessLogEnabled, h.AccessLogFormat,
		h.ErrorLogEnabled,
		headers, locs, h.RateLimitProfileID, h.CertificateID, h.UpstreamID, h.WAFEnabled, h.SecurityHeadersPreset,
		h.ListenHTTP, h.ListenHTTPS, h.HTTP2, h.ClientMaxBodySize,
		h.ConnectTimeout, h.SendTimeout, h.ReadTimeout, h.ProxyProtocol, methods,
	)
	out, err := scanHost(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}

func (s *Store) SoftDeleteHost(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE proxy_hosts SET deleted_at=now(), enabled=false, updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetHostEnabled(ctx context.Context, id uuid.UUID, enabled bool) (models.ProxyHost, error) {
	h, err := s.GetHost(ctx, id)
	if err != nil {
		return h, err
	}
	h.Enabled = enabled
	return s.UpdateHost(ctx, h)
}

func (s *Store) ListAllActiveHosts(ctx context.Context) ([]models.ProxyHost, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+hostSelectCols+` FROM proxy_hosts WHERE deleted_at IS NULL ORDER BY primary_domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ProxyHost
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
