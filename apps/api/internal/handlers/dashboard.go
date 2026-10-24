package handlers

import (
	"net/http"
	"time"

	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/metrics"
	"github.com/nginx-proxy-waf/api/internal/models"
)

// DashboardHandler — KPI summary for UI (REQ-UI-010, REQ-LB-012, REQ-OBS-007).
type DashboardHandler struct {
	Store *db.Store
}

func (h *DashboardHandler) Summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, _ := h.Store.ListAllActiveHosts(ctx)
	enabled := 0
	for _, host := range hosts {
		if host.Enabled {
			enabled++
		}
	}
	ups, _ := h.Store.ListUpstreams(ctx)
	activeMembers, downMembers := 0, 0
	for _, u := range ups {
		upN, downN := memberStats(u)
		activeMembers += upN
		downMembers += downN
		metrics.UpstreamMembers.WithLabelValues(u.Name, "up").Set(float64(upN))
		metrics.UpstreamMembers.WithLabelValues(u.Name, "down").Set(float64(downN))
	}
	certs, _ := h.Store.ListCertificates(ctx)
	expiring := 0
	for _, c := range certs {
		if c.DaysRemaining != nil {
			metrics.CertExpiryDays.WithLabelValues(c.Name, c.ID.String()).Set(float64(*c.DaysRemaining))
			if *c.DaysRemaining <= 30 {
				expiring++
				if *c.DaysRemaining <= 14 {
					metrics.AlertsFired.WithLabelValues("cert_expiry").Inc()
				}
			}
		}
	}
	cfg, err := h.Store.LatestAppliedConfig(ctx)
	cfgStatus := "none"
	cfgVersion := 0
	if err == nil {
		cfgStatus = cfg.Status
		cfgVersion = cfg.Version
	}
	users, _ := h.Store.ListUsers(ctx)
	WriteJSON(w, http.StatusOK, map[string]any{
		"hosts_total":        len(hosts),
		"hosts_enabled":      enabled,
		"upstreams":          len(ups),
		"members_up":         activeMembers,
		"members_down":       downMembers,
		"certificates":       len(certs),
		"certs_expiring_30d": expiring,
		"config_status":      cfgStatus,
		"config_version":     cfgVersion,
		"users":              len(users),
		"generated_at":       time.Now().UTC().Format(time.RFC3339),
	})
}

func memberStats(u models.Upstream) (upN, downN int) {
	for _, m := range u.Members {
		if m.IsDown || m.IsDrain {
			downN++
		} else {
			upN++
		}
	}
	return
}
