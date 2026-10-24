package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

type rateProfileReq struct {
	Name              string  `json:"name"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
	ConnectionsPerIP  int     `json:"connections_per_ip"`
	RetryAfterSeconds int     `json:"retry_after_seconds"`
}

func normalizeRateProfile(req *rateProfileReq) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || req.RequestsPerSecond <= 0 || req.Burst < 0 || req.ConnectionsPerIP < 1 {
		return errors.New("name, rps>0, burst>=0, connections>=1 required")
	}
	if req.RetryAfterSeconds < 0 || req.RetryAfterSeconds > 3600 {
		return errors.New("retry_after_seconds must be 0..3600 (0 = derive from RPS)")
	}
	req.RetryAfterSeconds = nginxcfg.NormalizeRetryAfterSeconds(req.RetryAfterSeconds, req.RequestsPerSecond)
	return nil
}

func (h *MiscHandler) ListRateLimits(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.ListRateProfiles(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.RateLimitProfile{}
	}
	trusted, _ := h.Store.GetSetting(r.Context(), "trusted_proxies")
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":               items,
		"trusted_proxies_set": strings.TrimSpace(trusted) != "",
		"ip_rate_active":      strings.TrimSpace(trusted) != "",
		"note":                "IP-based limits require trusted_proxies (real client IP)",
	})
}

func (h *MiscHandler) CreateRateLimit(w http.ResponseWriter, r *http.Request) {
	var req rateProfileReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if err := normalizeRateProfile(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	created, err := h.Store.CreateRateProfile(r.Context(), models.RateLimitProfile{
		Name: req.Name, RequestsPerSecond: req.RequestsPerSecond,
		Burst: req.Burst, ConnectionsPerIP: req.ConnectionsPerIP,
		RetryAfterSeconds: req.RetryAfterSeconds,
	})
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "could not create profile")
		return
	}
	writeAudit(h.Store, r, "rate.create", "rate_limit_profile", created.ID.String(), map[string]string{"name": created.Name})
	WriteJSON(w, http.StatusCreated, created)
}

func (h *MiscHandler) UpdateRateLimit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	var req rateProfileReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if err := normalizeRateProfile(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	updated, err := h.Store.UpdateRateProfile(r.Context(), models.RateLimitProfile{
		ID: id, Name: req.Name, RequestsPerSecond: req.RequestsPerSecond,
		Burst: req.Burst, ConnectionsPerIP: req.ConnectionsPerIP,
		RetryAfterSeconds: req.RetryAfterSeconds,
	})
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "profile not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "update failed")
		return
	}
	writeAudit(h.Store, r, "rate.update", "rate_limit_profile", id.String(), map[string]string{"name": updated.Name})
	WriteJSON(w, http.StatusOK, updated)
}

func (h *MiscHandler) DeleteRateLimit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if err := h.Store.DeleteRateProfile(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "profile not found")
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	writeAudit(h.Store, r, "rate.delete", "rate_limit_profile", id.String(), nil)
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
