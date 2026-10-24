package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

type HostHandler struct {
	Store     *db.Store
	ApplyHook func(ctx context.Context) error // nginx apply after host mutations (REQ-PROXY-003/004/010)
}

func (h *HostHandler) applyNginx(w http.ResponseWriter, r *http.Request) bool {
	if h.ApplyHook == nil {
		return true
	}
	if err := h.ApplyHook(r.Context()); err != nil {
		WriteError(w, http.StatusBadGateway, "apply_failed", err.Error())
		return false
	}
	return true
}

func (h *HostHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit
	items, total, err := h.Store.ListHosts(r.Context(), q, limit, offset)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page})
}

func (h *HostHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	host, err := h.Store.GetHost(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "host not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	WriteJSON(w, http.StatusOK, host)
}

func (h *HostHandler) Create(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid body")
		return
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(body, &raw)
	var host models.ProxyHost
	if err := json.Unmarshal(body, &host); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	normalizeHost(&host)
	applyCreateBoolDefaults(&host, raw)
	host.WAFEnabled = true // REQ-WAF-005 default on; patch to disable
	nginxcfg.NormalizeHostFields(&host)
	if err := nginxcfg.ValidateHost(host); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	created, err := h.Store.CreateHost(r.Context(), host)
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "could not create host")
		return
	}
	writeAudit(h.Store, r, "host.create", "proxy_host", created.ID.String(), map[string]string{"domain": created.PrimaryDomain})
	if !h.applyNginx(w, r) {
		_ = h.Store.SoftDeleteHost(r.Context(), created.ID)
		return
	}
	WriteJSON(w, http.StatusCreated, created)
}

func (h *HostHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	existing, err := h.Store.GetHost(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "host not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	var patch models.ProxyHost
	if err := DecodeJSON(r, &patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	patch.ID = existing.ID
	normalizeHost(&patch)
	nginxcfg.NormalizeHostFields(&patch)
	if err := nginxcfg.ValidateHost(patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	updated, err := h.Store.UpdateHost(r.Context(), patch)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "update failed")
		return
	}
	writeAudit(h.Store, r, "host.update", "proxy_host", updated.ID.String(), map[string]string{"domain": updated.PrimaryDomain})
	if !h.applyNginx(w, r) {
		return
	}
	WriteJSON(w, http.StatusOK, updated)
}

func (h *HostHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if err := h.Store.SoftDeleteHost(r.Context(), id); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "host not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	writeAudit(h.Store, r, "host.delete", "proxy_host", id.String(), nil)
	if !h.applyNginx(w, r) {
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted", "applied": "true"})
}

func (h *HostHandler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setEnabled(w, r, true)
}

func (h *HostHandler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setEnabled(w, r, false)
}

func (h *HostHandler) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	host, err := h.Store.SetHostEnabled(r.Context(), id, enabled)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "host not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "update failed")
		return
	}
	action := "host.disable"
	if enabled {
		action = "host.enable"
	}
	writeAudit(h.Store, r, action, "proxy_host", id.String(), nil)
	if !h.applyNginx(w, r) {
		return
	}
	WriteJSON(w, http.StatusOK, host)
}

func (h *HostHandler) Probe(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	host, err := h.Store.GetHost(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "host not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	result := nginxcfg.ProbeHostUpstream(host, 5*time.Second)
	writeAudit(h.Store, r, "host.probe", "proxy_host", id.String(), map[string]string{
		"ok": strconv.FormatBool(result.OK), "target": result.Target,
	})
	status := http.StatusOK
	if !result.OK {
		status = http.StatusBadGateway
	}
	WriteJSON(w, status, result)
}

func applyCreateBoolDefaults(h *models.ProxyHost, raw map[string]json.RawMessage) {
	if _, ok := raw["listen_http"]; !ok {
		h.ListenHTTP = true
	}
	if _, ok := raw["listen_https"]; !ok {
		h.ListenHTTPS = true
	}
	if _, ok := raw["http2"]; !ok {
		h.HTTP2 = true
	}
	if _, ok := raw["access_log_enabled"]; !ok {
		h.AccessLogEnabled = true
	}
	if _, ok := raw["error_log_enabled"]; !ok {
		h.ErrorLogEnabled = true
	}
	if _, ok := raw["enabled"]; !ok {
		h.Enabled = true
	}
}

func normalizeHost(h *models.ProxyHost) {
	h.PrimaryDomain = strings.ToLower(strings.TrimSpace(h.PrimaryDomain))
	if h.PathPrefix == "" {
		h.PathPrefix = "/"
	}
	if h.UpstreamScheme == "" {
		h.UpstreamScheme = "http"
	}
	if h.UpstreamID != nil {
		// Columns remain NOT NULL; pool binding uses upstream_id for render.
		if h.UpstreamHost == "" {
			h.UpstreamHost = "pool.local"
		}
		if h.UpstreamPort == 0 {
			h.UpstreamPort = 80
		}
	} else if h.UpstreamPort == 0 {
		if h.UpstreamScheme == "https" {
			h.UpstreamPort = 443
		} else {
			h.UpstreamPort = 80
		}
	}
	for i := range h.Aliases {
		h.Aliases[i] = strings.ToLower(strings.TrimSpace(h.Aliases[i]))
	}
	if h.SecurityHeadersPreset == "" {
		h.SecurityHeadersPreset = "none"
	}
	if h.ProxyProtocol == "" {
		h.ProxyProtocol = "http"
	}
}
