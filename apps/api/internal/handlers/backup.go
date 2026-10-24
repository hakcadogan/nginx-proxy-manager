package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/middleware"
)

// BackupHandler — logical backup/restore of control-plane state (REQ-OBS-004/005, REQ-API-014, REQ-DATA-007).
// Private keys are NOT included; only certificate metadata and config renders.
type BackupHandler struct {
	Store *db.Store
	Cfg   config.Config
}

type backupArtifact struct {
	Version     string          `json:"version"`
	CreatedAt   time.Time       `json:"created_at"`
	Hosts       json.RawMessage `json:"hosts"`
	Upstreams   json.RawMessage `json:"upstreams"`
	CertMeta    json.RawMessage `json:"certificates_meta"`
	ConfigLast  json.RawMessage `json:"config_last_applied,omitempty"`
	WAFPolicies json.RawMessage `json:"waf_policies"`
	IPPolicies  json.RawMessage `json:"ip_policies"`
	Settings    json.RawMessage `json:"settings"`
	Note        string          `json:"note"`
}

func (h *BackupHandler) Export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, err := h.Store.ListAllActiveHosts(ctx)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "hosts export failed")
		return
	}
	ups, err := h.Store.ListUpstreams(ctx)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "upstreams export failed")
		return
	}
	certs, err := h.Store.ListCertificates(ctx)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "certs export failed")
		return
	}
	// Strip any accidental key material fields — meta only
	certMeta := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		certMeta = append(certMeta, map[string]any{
			"id": c.ID, "name": c.Name, "kind": c.Kind, "domains": c.Domains,
			"not_after": c.NotAfter, "auto_renew": c.AutoRenew,
		})
	}
	pols, _ := h.Store.ListWAFPolicies(ctx)
	ips, _ := h.Store.ListIPPolicies(ctx, "")
	settings := map[string]string{}
	for _, k := range []string{
		"audit_retention_days", "security_events_retention_days", "config_versions_retention",
		"log_rotate_enabled", "log_rotate_max_mb", "log_rotate_keep", "log_rotate_interval_min",
		"ids_enforcement", "ids_protected_cidrs", "ids_detection",
	} {
		if v, err := h.Store.GetSetting(ctx, k); err == nil {
			settings[k] = v
		}
	}
	var cfgLast json.RawMessage
	if v, err := h.Store.LatestAppliedConfig(ctx); err == nil {
		b, _ := json.Marshal(map[string]any{
			"version": v.Version, "checksum": v.Checksum, "status": v.Status, "created_at": v.CreatedAt,
		})
		cfgLast = b
	}
	hb, _ := json.Marshal(hosts)
	ub, _ := json.Marshal(ups)
	cb, _ := json.Marshal(certMeta)
	wb, _ := json.Marshal(pols)
	ib, _ := json.Marshal(ips)
	sb, _ := json.Marshal(settings)

	art := backupArtifact{
		Version:     "1",
		CreatedAt:   time.Now().UTC(),
		Hosts:       hb,
		Upstreams:   ub,
		CertMeta:    cb,
		ConfigLast:  cfgLast,
		WAFPolicies: wb,
		IPPolicies:  ib,
		Settings:    sb,
		Note:        "Private keys and ACME account secrets are excluded. Restore rehydrates declarative state; re-issue certs as needed.",
	}
	writeAudit(h.Store, r, "backup.export", "backup", "", map[string]string{})
	w.Header().Set("Content-Disposition", "attachment; filename=nsp-backup.json")
	WriteJSON(w, http.StatusOK, art)
}

func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var art backupArtifact
	if err := DecodeJSON(r, &art); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid backup json")
		return
	}
	if art.Version != "1" {
		WriteError(w, http.StatusBadRequest, "validation_failed", "unsupported backup version")
		return
	}
	var settings map[string]string
	if len(art.Settings) > 0 {
		_ = json.Unmarshal(art.Settings, &settings)
		for k, v := range settings {
			_ = h.Store.SetSetting(r.Context(), k, v)
		}
	}
	writeAudit(h.Store, r, "backup.restore", "backup", "", map[string]string{
		"actor": sess.Email, "note": "settings restored; hosts/upstreams require apply workflow",
	})
	WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": "settings restored; full host rehydration via declarative apply — see runbook",
		"hosts":   json.RawMessage(art.Hosts),
	})
}

func (h *BackupHandler) Retention(w http.ResponseWriter, r *http.Request) {
	stats, err := h.Store.RunRetention(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "retention failed")
		return
	}
	writeAudit(h.Store, r, "retention.run", "platform", "", stats)
	WriteJSON(w, http.StatusOK, map[string]any{"deleted": stats})
}
