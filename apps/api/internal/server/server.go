package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/nginx-proxy-waf/api/internal/auth"
	"github.com/nginx-proxy-waf/api/internal/certs"
	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/crowdsec"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/handlers"
	"github.com/nginx-proxy-waf/api/internal/metrics"
	"github.com/nginx-proxy-waf/api/internal/middleware"
)

func New(cfg config.Config, store *db.Store, sessions *auth.SessionStore, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	authH := &handlers.AuthHandler{Store: store, Sessions: sessions, Cfg: cfg}
	cfgH := &handlers.ConfigHandler{Store: store, Cfg: cfg}
	hostH := &handlers.HostHandler{Store: store, ApplyHook: cfgH.ApplyNow}
	userH := &handlers.UserHandler{Store: store}
	miscH := &handlers.MiscHandler{Store: store, AppVersion: "0.6.0-production"}
	certH := &handlers.CertHandler{
		Store: store, Cfg: cfg, FS: &certs.Store{Root: cfg.CertsDir},
		ApplyHook: cfgH.ApplyNow,
	}
	upH := &handlers.UpstreamHandler{Store: store, ApplyHook: cfgH.ApplyNow}
	wafH := &handlers.WAFHandler{
		Store: store, ModsecDir: cfg.ModsecDir,
		ApplyHook: func(r *http.Request) {
			_ = cfgH.ApplyNow(r.Context())
		},
	}
	csClient := &crowdsec.Client{
		BaseURL: cfg.CrowdSecLAPIURL, BouncerKey: cfg.CrowdSecBouncerKey,
		AgentURL: cfg.CrowdSecAgentURL, AgentToken: cfg.CrowdSecAgentToken,
	}
	idsH := &handlers.IDSHandler{
		Store: store, CS: csClient, FailOpen: cfg.IDSFailOpen,
		CfgApply: cfgH.ApplyNow,
	}
	tokH := &handlers.TokenHandler{Store: store}
	bakH := &handlers.BackupHandler{Store: store, Cfg: cfg}
	dashH := &handlers.DashboardHandler{Store: store}
	setH := &handlers.SettingsHandler{Store: store}
	logsH := &handlers.LogsHandler{
		Store: store, Cfg: cfg,
		Reopen: cfgH.ReopenLogs,
	}

	authMW := &middleware.Auth{Sessions: sessions, Store: store, Cfg: cfg}
	loginLimit := middleware.NewAPIRateLimit(30, time.Minute)

	mux.HandleFunc("GET /health", miscH.Health)
	mux.HandleFunc("GET /api/v1/health", miscH.Health)
	mux.HandleFunc("GET /api/v1/version", miscH.Version)
	mux.Handle("GET /metrics", metrics.Handler())

	mux.HandleFunc("GET /api/v1/auth/bootstrap/status", authH.BootstrapStatus)
	mux.HandleFunc("POST /api/v1/auth/bootstrap", authH.Bootstrap)
	mux.Handle("POST /api/v1/auth/login", loginLimit.Middleware(http.HandlerFunc(authH.Login)))
	mux.Handle("POST /api/v1/auth/mfa/login", loginLimit.Middleware(http.HandlerFunc(authH.MFALogin)))

	protect := func(perm auth.Permission, h http.HandlerFunc) http.Handler {
		return authMW.Middleware(middleware.Require(perm)(h))
	}
	protectIdem := func(perm auth.Permission, h http.HandlerFunc) http.Handler {
		return authMW.Middleware(middleware.Require(perm)(middleware.Idempotency(store)(h)))
	}

	mux.Handle("POST /api/v1/auth/logout", protect(auth.PermHostsRead, authH.Logout))
	mux.Handle("GET /api/v1/auth/me", protect(auth.PermHostsRead, authH.Me))
	mux.Handle("POST /api/v1/auth/mfa/enroll", protect(auth.PermHostsRead, authH.MFAEnroll))
	mux.Handle("POST /api/v1/auth/mfa/confirm", protect(auth.PermHostsRead, authH.MFAConfirm))
	mux.Handle("POST /api/v1/auth/mfa/disable", protect(auth.PermHostsRead, authH.MFADisable))

	mux.Handle("GET /api/v1/hosts", protect(auth.PermHostsRead, hostH.List))
	mux.Handle("POST /api/v1/hosts", protect(auth.PermHostsWrite, hostH.Create))
	mux.Handle("GET /api/v1/hosts/{id}", protect(auth.PermHostsRead, hostH.Get))
	mux.Handle("PATCH /api/v1/hosts/{id}", protect(auth.PermHostsWrite, hostH.Update))
	mux.Handle("DELETE /api/v1/hosts/{id}", protect(auth.PermHostsWrite, hostH.Delete))
	mux.Handle("POST /api/v1/hosts/{id}/enable", protect(auth.PermHostsWrite, hostH.Enable))
	mux.Handle("POST /api/v1/hosts/{id}/disable", protect(auth.PermHostsWrite, hostH.Disable))
	mux.Handle("POST /api/v1/hosts/{id}/probe", protect(auth.PermHostsRead, hostH.Probe))

	mux.Handle("GET /api/v1/settings/network", protect(auth.PermConfigRead, setH.GetNetwork))
	mux.Handle("PUT /api/v1/settings/network", protect(auth.PermConfigWrite, setH.PutNetwork))
	mux.Handle("GET /api/v1/settings/logs", protect(auth.PermConfigRead, setH.GetLogs))
	mux.Handle("PUT /api/v1/settings/logs", protect(auth.PermConfigWrite, setH.PutLogs))
	mux.Handle("POST /api/v1/ops/log-rotate", protect(auth.PermConfigWrite, logsH.RotateNow))

	mux.Handle("POST /api/v1/config/validate", protect(auth.PermConfigWrite, cfgH.Validate))
	mux.Handle("POST /api/v1/config/apply", protectIdem(auth.PermConfigWrite, cfgH.Apply))
	mux.Handle("POST /api/v1/config/rollback", protectIdem(auth.PermConfigWrite, cfgH.Rollback))
	mux.Handle("GET /api/v1/config/status", protect(auth.PermConfigRead, cfgH.Status))
	mux.Handle("GET /api/v1/config/versions", protect(auth.PermConfigRead, cfgH.Versions))
	mux.Handle("GET /api/v1/config/versions/{id}", protect(auth.PermConfigRead, cfgH.GetVersion))

	mux.Handle("GET /api/v1/rate-limits", protect(auth.PermRateRead, miscH.ListRateLimits))
	mux.Handle("POST /api/v1/rate-limits", protect(auth.PermRateWrite, miscH.CreateRateLimit))
	mux.Handle("PATCH /api/v1/rate-limits/{id}", protect(auth.PermRateWrite, miscH.UpdateRateLimit))
	mux.Handle("DELETE /api/v1/rate-limits/{id}", protect(auth.PermRateWrite, miscH.DeleteRateLimit))
	mux.Handle("GET /api/v1/audit-logs", protect(auth.PermAuditRead, miscH.ListAudit))

	mux.Handle("GET /api/v1/users", protect(auth.PermUsersWrite, userH.List))
	mux.Handle("POST /api/v1/users", protect(auth.PermUsersWrite, userH.Create))
	mux.Handle("PATCH /api/v1/users/{id}", protect(auth.PermUsersWrite, userH.Patch))
	mux.Handle("DELETE /api/v1/users/{id}", protect(auth.PermUsersWrite, userH.Delete))
	mux.Handle("POST /api/v1/users/{id}/unlock", protect(auth.PermUsersWrite, userH.Unlock))

	mux.Handle("GET /api/v1/tokens", protect(auth.PermHostsRead, tokH.List))
	mux.Handle("POST /api/v1/tokens", protect(auth.PermHostsWrite, tokH.Create))
	mux.Handle("DELETE /api/v1/tokens/{id}", protect(auth.PermHostsWrite, tokH.Delete))

	mux.Handle("GET /api/v1/backup", protect(auth.PermConfigRead, bakH.Export))
	mux.Handle("POST /api/v1/backup/restore", protect(auth.PermConfigWrite, bakH.Restore))
	mux.Handle("POST /api/v1/ops/retention", protect(auth.PermConfigWrite, bakH.Retention))
	mux.Handle("GET /api/v1/dashboard", protect(auth.PermHostsRead, dashH.Summary))

	mux.Handle("GET /api/v1/certificates", protect(auth.PermHostsRead, certH.List))
	mux.Handle("GET /api/v1/certificates/{id}", protect(auth.PermHostsRead, certH.Get))
	mux.Handle("GET /api/v1/certificates/ops", protect(auth.PermAuditRead, certH.ListOps))
	mux.Handle("POST /api/v1/certificates/upload", protect(auth.PermConfigWrite, certH.Upload))
	mux.Handle("POST /api/v1/certificates/self-signed", protect(auth.PermConfigWrite, certH.SelfSigned))
	mux.Handle("POST /api/v1/certificates/private-ca", protect(auth.PermConfigWrite, certH.PrivateCA))
	mux.Handle("POST /api/v1/certificates/acme/issue", protect(auth.PermConfigWrite, certH.ACMEIssue))
	mux.Handle("POST /api/v1/certificates/{id}/renew", protect(auth.PermConfigWrite, certH.Renew))
	mux.Handle("POST /api/v1/certificates/{id}/rollback", protect(auth.PermConfigWrite, certH.Rollback))
	mux.Handle("POST /api/v1/certificates/{id}/bind", protect(auth.PermConfigWrite, certH.Bind))
	mux.Handle("DELETE /api/v1/certificates/{id}", protect(auth.PermConfigWrite, certH.Delete))

	mux.Handle("GET /api/v1/upstreams", protect(auth.PermHostsRead, upH.List))
	mux.Handle("POST /api/v1/upstreams", protect(auth.PermHostsWrite, upH.Create))
	mux.Handle("GET /api/v1/upstreams/{id}", protect(auth.PermHostsRead, upH.Get))
	mux.Handle("PATCH /api/v1/upstreams/{id}", protect(auth.PermHostsWrite, upH.Update))
	mux.Handle("DELETE /api/v1/upstreams/{id}", protect(auth.PermHostsWrite, upH.Delete))
	mux.Handle("POST /api/v1/upstreams/{id}/members", protect(auth.PermHostsWrite, upH.AddMember))
	mux.Handle("PATCH /api/v1/upstreams/{id}/members/{mid}", protect(auth.PermHostsWrite, upH.UpdateMember))
	mux.Handle("DELETE /api/v1/upstreams/{id}/members/{mid}", protect(auth.PermHostsWrite, upH.DeleteMember))
	mux.Handle("GET /api/v1/upstreams/{id}/health", protect(auth.PermHostsRead, upH.Health))

	mux.Handle("GET /api/v1/waf/policies", protect(auth.PermConfigRead, wafH.ListPolicies))
	mux.Handle("GET /api/v1/waf/policies/{id}", protect(auth.PermConfigRead, wafH.GetPolicy))
	mux.Handle("PATCH /api/v1/waf/policies/{id}", protect(auth.PermConfigWrite, wafH.PatchPolicy))
	mux.Handle("POST /api/v1/waf/policies/host", protect(auth.PermConfigWrite, wafH.UpsertHostPolicy))
	mux.Handle("GET /api/v1/waf/exceptions", protect(auth.PermConfigRead, wafH.ListExceptions))
	mux.Handle("POST /api/v1/waf/exceptions", protect(auth.PermConfigWrite, wafH.CreateException))
	mux.Handle("PATCH /api/v1/waf/exceptions/{id}", protect(auth.PermConfigWrite, wafH.UpdateException))
	mux.Handle("DELETE /api/v1/waf/exceptions/{id}", protect(auth.PermConfigWrite, wafH.DeleteException))
	mux.Handle("GET /api/v1/waf/ua-allowlist", protect(auth.PermConfigRead, wafH.GetUAAllowlist))
	mux.Handle("PUT /api/v1/waf/ua-allowlist", protect(auth.PermConfigWrite, wafH.PutUAAllowlist))
	mux.Handle("GET /api/v1/waf/ip-allowlist", protect(auth.PermConfigRead, wafH.GetIPAllowlist))
	mux.Handle("PUT /api/v1/waf/ip-allowlist", protect(auth.PermConfigWrite, wafH.PutIPAllowlist))
	mux.Handle("GET /api/v1/waf/modsec-settings", protect(auth.PermConfigRead, wafH.GetModSecSettings))
	mux.Handle("PUT /api/v1/waf/modsec-settings", protect(auth.PermConfigWrite, wafH.PutModSecSettings))
	mux.Handle("GET /api/v1/waf/custom-rules", protect(auth.PermConfigRead, wafH.GetCustomRules))
	mux.Handle("PUT /api/v1/waf/custom-rules", protect(auth.PermConfigWrite, wafH.PutCustomRules))
	mux.Handle("GET /api/v1/waf/crs-rules", protect(auth.PermConfigRead, wafH.ListCRSRules))
	mux.Handle("PATCH /api/v1/waf/crs-rules/{id}", protect(auth.PermConfigWrite, wafH.PatchCRSRule))
	mux.Handle("GET /api/v1/waf/events", protect(auth.PermAuditRead, wafH.ListEvents))
	mux.Handle("GET /api/v1/waf/events/{id}", protect(auth.PermAuditRead, wafH.GetEvent))
	mux.Handle("GET /api/v1/waf/events/{id}/suggest-exception", protect(auth.PermConfigRead, wafH.SuggestException))
	mux.Handle("GET /api/v1/waf/report", protect(auth.PermAuditRead, wafH.AttackReport))

	mux.Handle("GET /api/v1/ids/decisions", protect(auth.PermConfigRead, idsH.ListDecisions))
	mux.Handle("POST /api/v1/ids/bans", protect(auth.PermConfigWrite, idsH.CreateBan))
	mux.Handle("DELETE /api/v1/ids/bans/{id}", protect(auth.PermConfigWrite, idsH.DeletePolicy))
	mux.Handle("GET /api/v1/ids/allowlist", protect(auth.PermConfigRead, idsH.ListAllow))
	mux.Handle("POST /api/v1/ids/allowlist", protect(auth.PermConfigWrite, idsH.CreateAllow))
	mux.Handle("DELETE /api/v1/ids/allowlist/{id}", protect(auth.PermConfigWrite, idsH.DeletePolicy))
	mux.Handle("GET /api/v1/ids/denylist", protect(auth.PermConfigRead, idsH.ListDeny))
	mux.Handle("POST /api/v1/ids/denylist", protect(auth.PermConfigWrite, idsH.CreateDeny))
	mux.Handle("DELETE /api/v1/ids/denylist/{id}", protect(auth.PermConfigWrite, idsH.DeletePolicy))
	mux.Handle("POST /api/v1/ids/policies/bulk-create", protect(auth.PermConfigWrite, idsH.BulkCreatePolicies))
	mux.Handle("POST /api/v1/ids/policies/bulk-delete", protect(auth.PermConfigWrite, idsH.BulkDeletePolicies))
	mux.Handle("GET /api/v1/ids/history", protect(auth.PermAuditRead, idsH.ListHistory))
	mux.Handle("GET /api/v1/ids/protected", protect(auth.PermConfigRead, idsH.GetProtected))
	mux.Handle("PUT /api/v1/ids/protected", protect(auth.PermConfigWrite, idsH.PutProtected))
	mux.Handle("GET /api/v1/ids/detection", protect(auth.PermConfigRead, idsH.GetDetection))
	mux.Handle("PUT /api/v1/ids/detection", protect(auth.PermConfigWrite, idsH.PutDetection))
	mux.Handle("GET /api/v1/ids/enforcement", protect(auth.PermConfigRead, idsH.GetEnforcement))
	mux.Handle("PUT /api/v1/ids/enforcement", protect(auth.PermConfigWrite, idsH.PutEnforcement))
	mux.Handle("GET /api/v1/security-events", protect(auth.PermAuditRead, idsH.UnifiedEvents))

	var handler http.Handler = mux
	handler = middleware.AccessLog(log)(handler)
	handler = middleware.RequestID(handler)
	handler = middleware.CORS(cfg.PublicOrigin)(handler)
	return handler
}
