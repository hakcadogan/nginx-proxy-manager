package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds control-plane settings (REQ-OPS-005, REQ-SSL-*).
type Config struct {
	HTTPAddr           string
	DatabaseURL        string
	RedisAddr          string
	RedisPassword      string
	SessionSecret      string
	BootstrapToken     string
	PublicOrigin       string
	ConfigAgentURL     string
	ConfigAgentToken   string
	NginxStagingDir    string
	SessionTTL         time.Duration
	CookieSecure       bool
	CookieName         string
	CSRFCookieName     string
	CertsDir           string
	ACMEWebRoot        string
	ACMEAccountDir     string
	ACMEEmail          string
	CloudflareAPIToken string
	ACMEUseMockDNS     bool
	RenewInterval      time.Duration
	ModsecDir          string
	ModsecAuditLog     string
	CrowdSecLAPIURL    string
	CrowdSecBouncerKey string
	CrowdSecAgentURL   string
	CrowdSecAgentToken string
	IDSFailOpen        bool
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:           getenv("HTTP_ADDR", ":8081"),
		DatabaseURL:        getenv("DATABASE_URL", ""),
		RedisAddr:          getenv("REDIS_ADDR", "redis:6379"),
		RedisPassword:      os.Getenv("REDIS_PASSWORD"),
		SessionSecret:      os.Getenv("SESSION_SECRET"),
		BootstrapToken:     os.Getenv("BOOTSTRAP_TOKEN"),
		PublicOrigin:       getenv("PUBLIC_ORIGIN", "http://localhost:8080"),
		ConfigAgentURL:     getenv("CONFIG_AGENT_URL", "http://nginx:8090"),
		ConfigAgentToken:   os.Getenv("CONFIG_AGENT_TOKEN"),
		NginxStagingDir:    getenv("NGINX_STAGING_DIR", "/var/lib/nsp/staging"),
		SessionTTL:         durationEnv("SESSION_TTL", 12*time.Hour),
		CookieSecure:       boolEnv("COOKIE_SECURE", false),
		CookieName:         getenv("SESSION_COOKIE_NAME", "nsp_session"),
		CSRFCookieName:     getenv("CSRF_COOKIE_NAME", "nsp_csrf"),
		CertsDir:           getenv("CERTS_DIR", "/data/certs"),
		ACMEWebRoot:        getenv("ACME_WEBROOT", "/var/lib/nsp/acme-www"),
		ACMEAccountDir:     getenv("ACME_ACCOUNT_DIR", "/var/lib/nsp/acme"),
		ACMEEmail:          getenv("ACME_EMAIL", "admin@example.com"),
		CloudflareAPIToken: os.Getenv("CLOUDFLARE_API_TOKEN"),
		ACMEUseMockDNS:     boolEnv("ACME_USE_MOCK_DNS", false),
		RenewInterval:      durationEnv("CERT_RENEW_INTERVAL", time.Hour),
		ModsecDir:          getenv("MODSEC_DIR", "/var/lib/nsp/modsec"),
		ModsecAuditLog:     getenv("MODSEC_AUDIT_LOG", "/data/logs/nginx/modsec_audit.log"),
		CrowdSecLAPIURL:    getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080"),
		CrowdSecBouncerKey: os.Getenv("CROWDSEC_BOUNCER_KEY"),
		CrowdSecAgentURL:   getenv("CROWDSEC_AGENT_URL", "http://crowdsec:8091"),
		CrowdSecAgentToken: getenv("CROWDSEC_AGENT_TOKEN", os.Getenv("CONFIG_AGENT_TOKEN")),
		IDSFailOpen:        boolEnv("IDS_FAIL_OPEN", false),
	}
	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("DATABASE_URL is required")
	}
	if len(cfg.SessionSecret) < 32 {
		return cfg, fmt.Errorf("SESSION_SECRET must be at least 32 characters")
	}
	if cfg.ConfigAgentToken == "" {
		return cfg, fmt.Errorf("CONFIG_AGENT_TOKEN is required")
	}
	return cfg, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func boolEnv(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func durationEnv(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
