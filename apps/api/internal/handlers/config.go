package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/metrics"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

type ConfigHandler struct {
	Store  *db.Store
	Cfg    config.Config
	Client *http.Client
}

func (h *ConfigHandler) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

type agentResp struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func (h *ConfigHandler) renderDesired(ctx context.Context) (string, string, error) {
	hosts, err := h.Store.ListAllActiveHosts(ctx)
	if err != nil {
		return "", "", err
	}
	profiles, err := h.Store.ListRateProfiles(ctx)
	if err != nil {
		return "", "", err
	}
	pm := map[string]models.RateLimitProfile{}
	for _, p := range profiles {
		pm[p.ID.String()] = p
	}
	certMap := map[string]nginxcfg.TLSPaths{}
	certs, err := h.Store.ListCertificates(ctx)
	if err != nil {
		return "", "", err
	}
	for _, c := range certs {
		// OCSP stapling only when chain has an issuer (ACME fullchain). Self-signed → nginx warn spam.
		kind := strings.ToLower(strings.TrimSpace(c.Kind))
		certMap[c.ID.String()] = nginxcfg.TLSPaths{
			CertPath: c.CertPath, KeyPath: c.KeyPath,
			OCSP: kind == "acme",
		}
	}
	ups, err := h.Store.ListUpstreams(ctx)
	if err != nil {
		return "", "", err
	}
	um := map[string]models.Upstream{}
	for _, u := range ups {
		um[u.ID.String()] = u
	}
	wafIn, err := h.buildWAFInput(ctx)
	if err != nil {
		return "", "", err
	}
	overlay, err := nginxcfg.RenderModSecOverlay(*wafIn)
	if err != nil {
		return "", "", err
	}
	if err := WriteWAFOverlay(h.Cfg.ModsecDir, overlay); err != nil {
		return "", "", fmt.Errorf("write waf overlay: %w", err)
	}
	if err := WriteUAAllowlistFile(h.Cfg.ModsecDir, wafIn.UAAllowlist); err != nil {
		return "", "", fmt.Errorf("write ua allowlist: %w", err)
	}
	ips, err := h.Store.ListIPPolicies(ctx, "")
	if err != nil {
		return "", "", err
	}
	trusted, _ := h.Store.GetSetting(ctx, "trusted_proxies")
	realIPHdr, _ := h.Store.GetSetting(ctx, "real_ip_header")
	if realIPHdr == "" {
		realIPHdr = "X-Forwarded-For"
	}
	idsEnforcement, _ := h.Store.GetSetting(ctx, "ids_enforcement")
	if idsEnforcement == "" {
		idsEnforcement = "active"
	}
	bundle, err := nginxcfg.RenderAll(nginxcfg.RenderInput{
		Hosts: hosts, Profiles: pm, Certs: certMap, Upstreams: um, WAF: wafIn,
		IPPolicies: ips, ACMEWebRoot: h.Cfg.ACMEWebRoot,
		TrustedProxies: trusted, RealIPHeader: realIPHdr,
		IDSEnforcement: idsEnforcement,
	})
	if err != nil {
		return "", "", err
	}
	return nginxcfg.EncodeBundle(bundle), bundle.Checksum, nil
}

func (h *ConfigHandler) buildWAFInput(ctx context.Context) (*nginxcfg.WAFRenderInput, error) {
	global, err := h.Store.GetGlobalWAFPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("global waf policy: %w", err)
	}
	policies, err := h.Store.ListWAFPolicies(ctx)
	if err != nil {
		return nil, err
	}
	hostPol := map[string]models.WAFPolicy{}
	for _, p := range policies {
		if p.Scope == "host" && p.HostID != nil {
			hostPol[p.HostID.String()] = p
		}
	}
	ex, err := h.Store.ListWAFExceptions(ctx, nil)
	if err != nil {
		return nil, err
	}
	hosts, err := h.Store.ListAllActiveHosts(ctx)
	if err != nil {
		return nil, err
	}
	domains := map[string]string{}
	for _, ho := range hosts {
		domains[ho.ID.String()] = ho.PrimaryDomain
	}
	uaRaw, _ := h.Store.GetSetting(ctx, settingUAAllowlist)
	modsec := nginxcfg.DefaultModSecGlobalSettings()
	if raw, _ := h.Store.GetSetting(ctx, settingModSecGlobal); raw != "" {
		_ = json.Unmarshal([]byte(raw), &modsec)
	}
	modsec.Normalize()
	custom := nginxcfg.CustomRulesBundle{Hosts: map[string]string{}}
	if raw, _ := h.Store.GetSetting(ctx, settingCustomRules); raw != "" {
		_ = json.Unmarshal([]byte(raw), &custom)
	}
	if custom.Hosts == nil {
		custom.Hosts = map[string]string{}
	}
	var disabled []string
	if raw, _ := h.Store.GetSetting(ctx, settingDisabledCRSRules); raw != "" {
		_ = json.Unmarshal([]byte(raw), &disabled)
	}
	disabled, _ = nginxcfg.NormalizeDisabledRuleIDs(disabled)
	return &nginxcfg.WAFRenderInput{
		Global: global, HostPolicy: hostPol, Exceptions: ex, HostDomains: domains,
		UAAllowlist:    parseUAAllowlistSetting(uaRaw),
		ModSecSettings: modsec,
		CustomRules:    custom,
		DisabledRules:  disabled,
	}, nil
}

// ApplyNow is used by SSL challenge/bind flows (REQ-SSL-011).
func (h *ConfigHandler) ApplyNow(ctx context.Context) error {
	rendered, _, err := h.renderDesired(ctx)
	if err != nil {
		return err
	}
	if err := h.writeStaging(rendered); err != nil {
		return err
	}
	ar, err := h.callAgent(ctx, "/v1/apply", map[string]string{
		"staging_conf": filepath.Join(h.Cfg.NginxStagingDir, "nginx.conf"),
	})
	if err != nil {
		return fmt.Errorf("%s", ar.Message)
	}
	return nil
}

func (h *ConfigHandler) writeStaging(rendered string) error {
	bundle := nginxcfg.DecodeBundle(rendered)
	if err := os.MkdirAll(h.Cfg.NginxStagingDir, 0o755); err != nil {
		return err
	}
	// NPM-style live dirs (bind-mounted) — must exist before nginx -t.
	if err := os.MkdirAll(nginxcfg.ProxyHostDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(nginxcfg.CustomConfDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(nginxcfg.ProxyHostLogDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(nginxcfg.ProxyHostErrLogDir, 0o755); err != nil {
		return err
	}
	// Clear previous generated proxy_host files, then write current set.
	entries, _ := os.ReadDir(nginxcfg.ProxyHostDir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			_ = os.Remove(filepath.Join(nginxcfg.ProxyHostDir, e.Name()))
		}
	}
	wroteHost := false
	for name, body := range bundle.ProxyHostFiles {
		base := filepath.Base(name)
		if base != name || !strings.HasSuffix(base, ".conf") {
			continue
		}
		path := filepath.Join(nginxcfg.ProxyHostDir, base)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		wroteHost = true
	}
	// nginx fails on empty include globs — keep a harmless placeholder when no hosts.
	if !wroteHost {
		_ = os.WriteFile(filepath.Join(nginxcfg.ProxyHostDir, "00-nsp-placeholder.conf"),
			[]byte("# NSP proxy_host — no enabled hosts\n"), 0o644)
	}
	// Custom drop-ins under CustomConfDir are operator-owned (REQ-PROXY-021);
	// never wipe or replace them on apply — only mkdir.
	path := filepath.Join(h.Cfg.NginxStagingDir, "nginx.conf")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(bundle.Main), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReopenLogs asks nginx to reopen log FDs after rotation (REQ-OBS-006).
func (h *ConfigHandler) ReopenLogs(ctx context.Context) error {
	_, err := h.callAgent(ctx, "/v1/reopen", map[string]any{})
	return err
}

func (h *ConfigHandler) callAgent(ctx context.Context, path string, body any) (agentResp, error) {
	var ar agentResp
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Cfg.ConfigAgentURL+path, bytes.NewReader(b))
	if err != nil {
		return ar, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", h.Cfg.ConfigAgentToken)
	res, err := h.client().Do(req)
	if err != nil {
		return ar, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(raw, &ar)
	if res.StatusCode >= 300 {
		if ar.Message == "" {
			ar.Message = string(raw)
		}
		return ar, fmt.Errorf("agent status %d: %s", res.StatusCode, ar.Message)
	}
	return ar, nil
}

func (h *ConfigHandler) Validate(w http.ResponseWriter, r *http.Request) {
	rendered, checksum, err := h.renderDesired(r.Context())
	if err != nil {
		WriteError(w, http.StatusUnprocessableEntity, "config_invalid", err.Error())
		return
	}
	if err := h.writeStaging(rendered); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "staging write failed")
		return
	}
	ar, err := h.callAgent(r.Context(), "/v1/validate", map[string]string{
		"staging_conf": filepath.Join(h.Cfg.NginxStagingDir, "nginx.conf"),
	})
	if err != nil {
		WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "checksum": checksum, "message": ar.Message, "error": err.Error(),
		})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "checksum": checksum, "message": ar.Message})
}

func (h *ConfigHandler) Apply(w http.ResponseWriter, r *http.Request) {
	rendered, checksum, err := h.renderDesired(r.Context())
	if err != nil {
		WriteError(w, http.StatusUnprocessableEntity, "config_invalid", err.Error())
		return
	}
	if err := h.writeStaging(rendered); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "staging write failed")
		return
	}
	verNum, err := h.Store.NextConfigVersion(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "version allocate failed")
		return
	}
	sess, _ := middleware.SessionFrom(r.Context())
	uid := sess.UserID
	cv, err := h.Store.SaveConfigVersion(r.Context(), models.ConfigVersion{
		Version:   verNum,
		Checksum:  checksum,
		Rendered:  rendered,
		Status:    "staged",
		CreatedBy: &uid,
	})
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "version save failed")
		return
	}

	ar, err := h.callAgent(r.Context(), "/v1/apply", map[string]string{
		"staging_conf": filepath.Join(h.Cfg.NginxStagingDir, "nginx.conf"),
	})
	if err != nil {
		_ = h.Store.UpdateConfigVersionStatus(r.Context(), cv.ID, "failed", ar.Message)
		writeAudit(h.Store, r, "config.apply_failed", "config_version", cv.ID.String(), map[string]string{"message": ar.Message})
		metrics.ConfigReloadTotal.WithLabelValues("failed").Inc()
		metrics.AlertsFired.WithLabelValues("reload_fail").Inc()
		WriteError(w, http.StatusConflict, "reload_failed", ar.Message)
		return
	}
	metrics.ConfigReloadTotal.WithLabelValues("ok").Inc()
	_ = h.Store.UpdateConfigVersionStatus(r.Context(), cv.ID, "applied", ar.Message)
	writeAudit(h.Store, r, "config.apply", "config_version", cv.ID.String(), map[string]any{"version": verNum, "checksum": checksum})
	WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "version": verNum, "checksum": checksum, "message": ar.Message, "id": cv.ID,
	})
}

func (h *ConfigHandler) Status(w http.ResponseWriter, r *http.Request) {
	latest, err := h.Store.LatestAppliedConfig(r.Context())
	if errors.Is(err, db.ErrNotFound) {
		WriteJSON(w, http.StatusOK, map[string]any{"applied": false})
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "status failed")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"applied": true,
		"version": latest.Version,
		"checksum": latest.Checksum,
		"status": latest.Status,
		"created_at": latest.CreatedAt,
	})
}

func (h *ConfigHandler) Versions(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.ListConfigVersions(r.Context(), 50)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *ConfigHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	v, err := h.Store.GetConfigVersion(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "version not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

type rollbackReq struct {
	VersionID string `json:"version_id"`
}

func (h *ConfigHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	var req rollbackReq
	if err := DecodeJSON(r, &req); err != nil || req.VersionID == "" {
		WriteError(w, http.StatusBadRequest, "validation_failed", "version_id required")
		return
	}
	id, err := uuid.Parse(req.VersionID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid version_id")
		return
	}
	v, err := h.Store.GetConfigVersion(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "version not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	if err := h.writeStaging(v.Rendered); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "staging write failed")
		return
	}
	ar, err := h.callAgent(r.Context(), "/v1/apply", map[string]string{
		"staging_conf": filepath.Join(h.Cfg.NginxStagingDir, "nginx.conf"),
	})
	if err != nil {
		WriteError(w, http.StatusConflict, "reload_failed", ar.Message)
		return
	}
	verNum, _ := h.Store.NextConfigVersion(r.Context())
	sess, _ := middleware.SessionFrom(r.Context())
	uid := sess.UserID
	cv, err := h.Store.SaveConfigVersion(r.Context(), models.ConfigVersion{
		Version:   verNum,
		Checksum:  v.Checksum,
		Rendered:  v.Rendered,
		Status:    "applied",
		Message:   fmt.Sprintf("rollback to version %d", v.Version),
		CreatedBy: &uid,
	})
	if err == nil {
		_ = h.Store.UpdateConfigVersionStatus(r.Context(), v.ID, "rolled_back", "selected for rollback")
	}
	writeAudit(h.Store, r, "config.rollback", "config_version", cv.ID.String(), map[string]any{"from": v.Version, "to": verNum})
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "version": verNum, "restored_from": v.Version})
}
