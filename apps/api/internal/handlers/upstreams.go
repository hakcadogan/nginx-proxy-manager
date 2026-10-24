package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

type UpstreamHandler struct {
	Store     *db.Store
	ApplyHook func(ctx context.Context) error // nginx apply after pool/member mutations (REQ-LB-011)
}

func (h *UpstreamHandler) applyNginx(r *http.Request) error {
	if h.ApplyHook == nil {
		return nil
	}
	return h.ApplyHook(r.Context())
}

func (h *UpstreamHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.ListUpstreams(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.Upstream{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *UpstreamHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	u, err := h.Store.GetUpstream(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "upstream not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	WriteJSON(w, http.StatusOK, u)
}

func (h *UpstreamHandler) Create(w http.ResponseWriter, r *http.Request) {
	var u models.Upstream
	if err := DecodeJSON(r, &u); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	u.Name = strings.TrimSpace(u.Name)
	applyUpstreamDefaults(&u)
	if err := nginxcfg.ValidateUpstream(u); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	created, err := h.Store.CreateUpstream(r.Context(), u)
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "could not create upstream")
		return
	}
	writeAudit(h.Store, r, "upstream.create", "upstream", created.ID.String(), map[string]string{"name": created.Name})
	_ = h.applyNginx(r) // empty pool — still refresh if hosts already reference id
	WriteJSON(w, http.StatusCreated, created)
}

func (h *UpstreamHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	existing, err := h.Store.GetUpstream(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "upstream not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	var patch models.Upstream
	if err := DecodeJSON(r, &patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	patch.ID = existing.ID
	if patch.Name == "" {
		patch.Name = existing.Name
	}
	applyUpstreamDefaults(&patch)
	if err := nginxcfg.ValidateUpstream(patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	updated, err := h.Store.UpdateUpstream(r.Context(), patch)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "update failed")
		return
	}
	writeAudit(h.Store, r, "upstream.update", "upstream", updated.ID.String(), map[string]string{"name": updated.Name})
	if err := h.applyNginx(r); err != nil {
		WriteError(w, http.StatusBadGateway, "apply_failed", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, updated)
}

func (h *UpstreamHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if err := h.Store.DeleteUpstream(r.Context(), id); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "upstream not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	writeAudit(h.Store, r, "upstream.delete", "upstream", id.String(), nil)
	if err := h.applyNginx(r); err != nil {
		WriteError(w, http.StatusBadGateway, "apply_failed", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *UpstreamHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if _, err := h.Store.GetUpstream(r.Context(), uid); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "upstream not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	var m models.UpstreamMember
	if err := DecodeJSON(r, &m); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	m.UpstreamID = uid
	m.Host = strings.ToLower(strings.TrimSpace(m.Host))
	if m.Weight < 1 {
		m.Weight = 1
	}
	if err := nginxcfg.ValidateMember(m); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	created, err := h.Store.CreateMember(r.Context(), m)
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "could not add member")
		return
	}
	writeAudit(h.Store, r, "upstream.member_add", "upstream_member", created.ID.String(), map[string]any{
		"upstream_id": uid.String(), "host": created.Host, "port": created.Port,
	})
	if err := h.applyNginx(r); err != nil {
		WriteError(w, http.StatusBadGateway, "apply_failed", err.Error())
		return
	}
	WriteJSON(w, http.StatusCreated, created)
}

func (h *UpstreamHandler) UpdateMember(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	mid, err := uuid.Parse(r.PathValue("mid"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid member id")
		return
	}
	existing, err := h.Store.GetMember(r.Context(), uid, mid)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "member not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid body")
		return
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(body, &raw)
	var patch models.UpstreamMember
	if err := json.Unmarshal(body, &patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	patch.ID = existing.ID
	patch.UpstreamID = uid
	if patch.Host == "" {
		patch.Host = existing.Host
	}
	if patch.Port == 0 {
		patch.Port = existing.Port
	}
	if patch.Weight < 1 {
		patch.Weight = existing.Weight
	}
	// max_conns: 0 = unlimited (valid). If key omitted, keep existing.
	if _, ok := raw["max_conns"]; !ok {
		patch.MaxConns = existing.MaxConns
	}
	// Bool flags: omit → keep existing (drain-only patches must not clear backup)
	if _, ok := raw["is_backup"]; !ok {
		patch.IsBackup = existing.IsBackup
	}
	if _, ok := raw["is_down"]; !ok {
		patch.IsDown = existing.IsDown
	}
	if _, ok := raw["is_drain"]; !ok {
		patch.IsDrain = existing.IsDrain
	}
	if _, ok := raw["admin_disabled"]; !ok {
		patch.AdminDisabled = existing.AdminDisabled
	}
	// Sync admin_disabled with explicit enable/disable / undrain so HC cannot re-enable.
	if _, ok := raw["is_down"]; ok {
		if patch.IsDown && !patch.IsDrain {
			patch.AdminDisabled = true
		}
		if !patch.IsDown {
			patch.AdminDisabled = false
		}
	}
	if _, ok := raw["is_drain"]; ok && !patch.IsDrain && !patch.IsDown {
		patch.AdminDisabled = false
	}
	patch.Host = strings.ToLower(strings.TrimSpace(patch.Host))
	if err := nginxcfg.ValidateMember(patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	updated, err := h.Store.UpdateMember(r.Context(), patch)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "update failed")
		return
	}
	writeAudit(h.Store, r, "upstream.member_update", "upstream_member", updated.ID.String(), map[string]any{
		"host": updated.Host, "port": updated.Port, "weight": updated.Weight,
		"is_drain": updated.IsDrain, "is_down": updated.IsDown, "is_backup": updated.IsBackup,
		"admin_disabled": updated.AdminDisabled,
	})
	if err := h.applyNginx(r); err != nil {
		WriteError(w, http.StatusBadGateway, "apply_failed", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, updated)
}

func (h *UpstreamHandler) DeleteMember(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	mid, err := uuid.Parse(r.PathValue("mid"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid member id")
		return
	}
	if err := h.Store.DeleteMember(r.Context(), uid, mid); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "member not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	writeAudit(h.Store, r, "upstream.member_delete", "upstream_member", mid.String(), nil)
	if err := h.applyNginx(r); err != nil {
		WriteError(w, http.StatusBadGateway, "apply_failed", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func applyUpstreamDefaults(u *models.Upstream) {
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
		u.NextUpstream = nginxcfg.DefaultNextUpstream
	}
	if u.NextUpstreamTimeout == "" {
		u.NextUpstreamTimeout = "0"
	}
}

func (h *UpstreamHandler) Health(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	u, err := h.Store.GetUpstream(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "upstream not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	type memberHealth struct {
		ID            string  `json:"id"`
		Host          string  `json:"host"`
		Port          int     `json:"port"`
		IsDown        bool    `json:"is_down"`
		IsDrain       bool    `json:"is_drain"`
		IsBackup      bool    `json:"is_backup"`
		AdminDisabled bool    `json:"admin_disabled"`
		LastCheckAt   *string `json:"last_check_at,omitempty"`
		LastCheckOK   *bool   `json:"last_check_ok,omitempty"`
	}
	out := make([]memberHealth, 0, len(u.Members))
	for _, m := range u.Members {
		mh := memberHealth{
			ID: m.ID.String(), Host: m.Host, Port: m.Port,
			IsDown: m.IsDown, IsDrain: m.IsDrain, IsBackup: m.IsBackup,
			AdminDisabled: m.AdminDisabled, LastCheckOK: m.LastCheckOK,
		}
		if m.LastCheckAt != nil {
			s := m.LastCheckAt.UTC().Format("2006-01-02T15:04:05Z")
			mh.LastCheckAt = &s
		}
		out = append(out, mh)
	}
	upN, downN := 0, 0
	for _, m := range u.Members {
		if m.IsDown || m.IsDrain {
			downN++
		} else {
			upN++
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"upstream_id":            u.ID,
		"health_check_enabled":   u.HealthCheckEnabled,
		"health_check_path":      u.HealthCheckPath,
		"health_check_mode":      "control_plane_probe", // not nginx Plus health_check
		"health_check_note":      "Nginx OSS has no native active health_check; API probes members and marks down + reload",
		"members_up":             upN,
		"members_down":           downN,
		"members":                out,
		"metrics_note":           "Request/error counters require nginx stub_status or an exporter; panel exposes member up/down gauges only",
	})
}
