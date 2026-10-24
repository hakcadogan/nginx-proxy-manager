package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

type User struct {
	ID                uuid.UUID  `json:"id"`
	Email             string     `json:"email"`
	PasswordHash      string     `json:"-"`
	Role              Role       `json:"role"`
	FailedLoginCount  int        `json:"failed_login_count,omitempty"`
	LockedUntil       *time.Time `json:"locked_until,omitempty"`
	MFASecret         string     `json:"-"`
	MFAEnabled        bool       `json:"mfa_enabled"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type APIToken struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Name       string     `json:"name"`
	TokenPrefix string    `json:"token_prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	// Token plaintext only returned once on create
	Token string `json:"token,omitempty"`
}

type HeaderRule struct {
	Action string `json:"action"` // add | remove
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}

type LocationRule struct {
	Path               string   `json:"path"`
	UpstreamScheme     string   `json:"upstream_scheme"`
	UpstreamHost       string   `json:"upstream_host"`
	UpstreamPort       int      `json:"upstream_port"`
	AllowedMethods     []string `json:"allowed_methods,omitempty"` // empty = all
	RateLimitProfileID string   `json:"rate_limit_profile_id,omitempty"`
}

type ProxyHost struct {
	ID                 uuid.UUID      `json:"id"`
	PrimaryDomain      string         `json:"primary_domain"`
	Aliases            []string       `json:"aliases"`
	UpstreamScheme     string         `json:"upstream_scheme"`
	UpstreamHost       string         `json:"upstream_host"`
	UpstreamPort       int            `json:"upstream_port"`
	PathPrefix         string         `json:"path_prefix"`
	Enabled            bool           `json:"enabled"`
	ForceHTTPS         bool           `json:"force_https"`
	WebsocketSupport   bool           `json:"websocket_support"`
	AccessLogEnabled   bool           `json:"access_log_enabled"`
	AccessLogFormat    string         `json:"access_log_format"` // main|combined|detailed|json
	ErrorLogEnabled    bool           `json:"error_log_enabled"`
	CustomHeaders      []HeaderRule   `json:"custom_headers"`
	Locations          []LocationRule `json:"locations"`
	RateLimitProfileID *uuid.UUID     `json:"rate_limit_profile_id,omitempty"`
	CertificateID      *uuid.UUID     `json:"certificate_id,omitempty"`
	UpstreamID             *uuid.UUID `json:"upstream_id,omitempty"`
	WAFEnabled             bool       `json:"waf_enabled"`
	SecurityHeadersPreset  string     `json:"security_headers_preset"`
	ListenHTTP             bool       `json:"listen_http"`
	ListenHTTPS            bool       `json:"listen_https"`
	HTTP2                  bool       `json:"http2"`
	ClientMaxBodySize      string     `json:"client_max_body_size"`
	ConnectTimeout         string     `json:"connect_timeout"`
	SendTimeout            string     `json:"send_timeout"`
	ReadTimeout            string     `json:"read_timeout"`
	ProxyProtocol          string     `json:"proxy_protocol"` // http | grpc
	AllowedMethods         []string   `json:"allowed_methods,omitempty"` // empty = all methods
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// IPPolicyHistory is an append-only ban/deny/allow audit trail (REQ-IDS-012).
type IPPolicyHistory struct {
	ID          int64     `json:"id"`
	PolicyID    *uuid.UUID `json:"policy_id,omitempty"`
	Action      string    `json:"action"`
	Kind        string    `json:"kind"`
	IPCIDR      string    `json:"ip_cidr"`
	Reason      string    `json:"reason"`
	Source      string    `json:"source"`
	CountryCode string    `json:"country_code,omitempty"`
	ActorEmail  string    `json:"actor_email,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// WAFPolicy controls ModSecurity engine mode / paranoia (REQ-WAF-003..006).
type WAFPolicy struct {
	ID                             uuid.UUID  `json:"id"`
	Name                           string     `json:"name"`
	Scope                          string     `json:"scope"` // global | host
	HostID                         *uuid.UUID `json:"host_id,omitempty"`
	Enabled                        bool       `json:"enabled"`
	EngineMode                     string     `json:"engine_mode"` // Off | DetectionOnly | On
	ParanoiaLevel                  int        `json:"paranoia_level"`
	AuditRelevantOnly              bool       `json:"audit_relevant_only"`
	InboundAnomalyScoreThreshold   int        `json:"inbound_anomaly_score_threshold"`
	OutboundAnomalyScoreThreshold  int        `json:"outbound_anomaly_score_threshold"`
	CreatedAt                      time.Time  `json:"created_at"`
	UpdatedAt                      time.Time  `json:"updated_at"`
}

type WAFException struct {
	ID         uuid.UUID  `json:"id"`
	PolicyID   uuid.UUID  `json:"policy_id"`
	HostID     *uuid.UUID `json:"host_id,omitempty"` // optional host scope (REQ-WAF-008)
	RuleID     string     `json:"rule_id"`
	PathPrefix string     `json:"path_prefix"`
	Argument   string     `json:"argument"`
	Reason     string     `json:"reason"`
	Enabled    bool       `json:"enabled"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// SecurityEvent is a masked WAF/IDS alert (REQ-WAF-009/010, REQ-OBS-003).
type SecurityEvent struct {
	ID             int64     `json:"id"`
	Source         string    `json:"source"`
	HostID         *uuid.UUID `json:"host_id,omitempty"`
	Domain         string    `json:"domain"`
	RuleID         string    `json:"rule_id"`
	Severity       int       `json:"severity"`
	Message        string    `json:"message"`
	URI            string    `json:"uri"`
	Method         string    `json:"method"`
	ClientIP       string    `json:"client_ip"`
	PayloadSummary string    `json:"payload_summary"`
	UniqueID       string    `json:"unique_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// IPPolicy is allow/deny/ban entry (REQ-IDS-005..008).
type IPPolicy struct {
	ID         uuid.UUID  `json:"id"`
	Kind       string     `json:"kind"` // allow | deny | ban
	IPCIDR     string     `json:"ip_cidr"`
	Reason     string     `json:"reason"`
	Source     string     `json:"source"` // manual | crowdsec
	ExternalID string     `json:"external_id,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Upstream is a backend pool (REQ-LB-001).
type Upstream struct {
	ID                    uuid.UUID         `json:"id"`
	Name                  string            `json:"name"`
	Algorithm             string            `json:"algorithm"`
	HashKey               string            `json:"hash_key"`
	Scheme                string            `json:"scheme"`
	SNI                   string            `json:"sni"`
	ConnectTimeout        string            `json:"connect_timeout"`
	SendTimeout           string            `json:"send_timeout"`
	ReadTimeout           string            `json:"read_timeout"`
	MaxFails               int              `json:"max_fails"`
	FailTimeout            string           `json:"fail_timeout"`
	HealthCheckEnabled     bool             `json:"health_check_enabled"`
	HealthCheckPath        string           `json:"health_check_path"`
	HealthCheckIntervalSec int              `json:"health_check_interval_sec"`
	// NextUpstream is space-separated proxy_next_upstream conditions (OSS).
	// Include "non_idempotent" only if POST/PUT retries are intentional (duplicate risk).
	NextUpstream        string           `json:"next_upstream"`
	NextUpstreamTries   int              `json:"next_upstream_tries"`   // 0 = nginx default
	NextUpstreamTimeout string           `json:"next_upstream_timeout"` // 0 = disabled
	Members             []UpstreamMember `json:"members,omitempty"`
	CreatedAt           time.Time        `json:"created_at"`
	UpdatedAt           time.Time        `json:"updated_at"`
}

type UpstreamMember struct {
	ID          uuid.UUID  `json:"id"`
	UpstreamID  uuid.UUID  `json:"upstream_id"`
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	Weight      int        `json:"weight"`
	MaxConns    int        `json:"max_conns"` // 0 = unlimited (omit from nginx); REQ-LB-001
	IsBackup      bool       `json:"is_backup"`
	IsDown        bool       `json:"is_down"`
	IsDrain       bool       `json:"is_drain"`
	AdminDisabled bool       `json:"admin_disabled"` // manual disable; health probe must not clear (REQ-LB-008/011)
	LastCheckAt   *time.Time `json:"last_check_at,omitempty"`
	LastCheckOK   *bool      `json:"last_check_ok,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ACMEOperation is an append-only ACME issue/renew/rollback log (REQ-SSL-017).
type ACMEOperation struct {
	ID            int64      `json:"id"`
	CertificateID *uuid.UUID `json:"certificate_id,omitempty"`
	Operation     string     `json:"operation"`
	Challenge     string     `json:"challenge,omitempty"`
	Domains       []string   `json:"domains"`
	Status        string     `json:"status"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	ActorEmail    string     `json:"actor_email,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// Certificate is public metadata only — never includes private key (REQ-SSL-013).
type Certificate struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Domains          []string   `json:"domains"`
	Kind             string     `json:"kind"`
	ACMEChallenge    *string    `json:"acme_challenge,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	NotAfter         *time.Time `json:"not_after,omitempty"`
	Issuer           string     `json:"issuer"`
	CertPath         string     `json:"-"`
	KeyPath          string     `json:"-"`
	AutoRenew        bool       `json:"auto_renew"`
	RenewAfterDays   int        `json:"renew_after_days"`
	DaysRemaining    *int       `json:"days_remaining,omitempty"`
	ExpiringSoon     bool       `json:"expiring_soon"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type RateLimitProfile struct {
	ID                 uuid.UUID `json:"id"`
	Name               string    `json:"name"`
	RequestsPerSecond  float64   `json:"requests_per_second"`
	Burst              int       `json:"burst"`
	ConnectionsPerIP   int       `json:"connections_per_ip"`
	RetryAfterSeconds  int       `json:"retry_after_seconds"` // REQ-RATE-005 — 429 Retry-After
	CreatedAt          time.Time `json:"created_at"`
}

type ConfigVersion struct {
	ID        uuid.UUID `json:"id"`
	Version   int       `json:"version"`
	Checksum  string    `json:"checksum"`
	Rendered  string    `json:"rendered,omitempty"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditLog struct {
	ID           int64           `json:"id"`
	ActorUserID  *uuid.UUID      `json:"actor_user_id,omitempty"`
	ActorEmail   string          `json:"actor_email"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	RequestID    string          `json:"request_id"`
	IP           string          `json:"ip"`
	Details      json.RawMessage `json:"details"`
	CreatedAt    time.Time       `json:"created_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Role      Role      `json:"role"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}
