package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

type SettingsHandler struct {
	Store *db.Store
}

type networkSettings struct {
	TrustedProxies string `json:"trusted_proxies"`
	RealIPHeader   string `json:"real_ip_header"`
}

func (h *SettingsHandler) GetNetwork(w http.ResponseWriter, r *http.Request) {
	trusted, _ := h.Store.GetSetting(r.Context(), "trusted_proxies")
	hdr, _ := h.Store.GetSetting(r.Context(), "real_ip_header")
	if hdr == "" {
		hdr = "X-Forwarded-For"
	}
	WriteJSON(w, http.StatusOK, networkSettings{TrustedProxies: trusted, RealIPHeader: hdr})
}

func (h *SettingsHandler) PutNetwork(w http.ResponseWriter, r *http.Request) {
	var body networkSettings
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	body.TrustedProxies = strings.TrimSpace(body.TrustedProxies)
	body.RealIPHeader = strings.TrimSpace(body.RealIPHeader)
	if body.RealIPHeader == "" {
		body.RealIPHeader = "X-Forwarded-For"
	}
	if _, err := nginxcfg.RenderRealIP(body.TrustedProxies, body.RealIPHeader); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	if err := h.Store.SetSetting(r.Context(), "trusted_proxies", body.TrustedProxies); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	if err := h.Store.SetSetting(r.Context(), "real_ip_header", body.RealIPHeader); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	writeAudit(h.Store, r, "settings.network", "platform_settings", "network", nil)
	WriteJSON(w, http.StatusOK, body)
}

type logSettings struct {
	Enabled     bool `json:"enabled"`
	MaxMB       int  `json:"max_mb"`
	Keep        int  `json:"keep"`
	IntervalMin int  `json:"interval_min"`
}

func (h *SettingsHandler) loadLogSettings(r *http.Request) logSettings {
	s := logSettings{Enabled: true, MaxMB: 100, Keep: 7, IntervalMin: 60}
	if v, _ := h.Store.GetSetting(r.Context(), "log_rotate_enabled"); v == "false" {
		s.Enabled = false
	}
	if v, _ := h.Store.GetSetting(r.Context(), "log_rotate_max_mb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.MaxMB = n
		}
	}
	if v, _ := h.Store.GetSetting(r.Context(), "log_rotate_keep"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.Keep = n
		}
	}
	if v, _ := h.Store.GetSetting(r.Context(), "log_rotate_interval_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.IntervalMin = n
		}
	}
	return s
}

func (h *SettingsHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, h.loadLogSettings(r))
}

func (h *SettingsHandler) PutLogs(w http.ResponseWriter, r *http.Request) {
	var body logSettings
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if body.MaxMB < 1 || body.MaxMB > 10240 {
		WriteError(w, http.StatusBadRequest, "validation_failed", "max_mb must be 1..10240")
		return
	}
	if body.Keep < 1 || body.Keep > 30 {
		WriteError(w, http.StatusBadRequest, "validation_failed", "keep must be 1..30")
		return
	}
	if body.IntervalMin < 5 || body.IntervalMin > 10080 {
		WriteError(w, http.StatusBadRequest, "validation_failed", "interval_min must be 5..10080")
		return
	}
	en := "true"
	if !body.Enabled {
		en = "false"
	}
	_ = h.Store.SetSetting(r.Context(), "log_rotate_enabled", en)
	_ = h.Store.SetSetting(r.Context(), "log_rotate_max_mb", strconv.Itoa(body.MaxMB))
	_ = h.Store.SetSetting(r.Context(), "log_rotate_keep", strconv.Itoa(body.Keep))
	_ = h.Store.SetSetting(r.Context(), "log_rotate_interval_min", strconv.Itoa(body.IntervalMin))
	writeAudit(h.Store, r, "settings.logs", "platform_settings", "logs", body)
	WriteJSON(w, http.StatusOK, body)
}
