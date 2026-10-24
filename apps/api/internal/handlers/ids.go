package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/crowdsec"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

type IDSHandler struct {
	Store    *db.Store
	CS       *crowdsec.Client
	CfgApply func(ctx context.Context) error
	FailOpen bool
}

func (h *IDSHandler) apply(r *http.Request) {
	if h.CfgApply == nil {
		return
	}
	_ = h.CfgApply(r.Context())
}

// applyAsync returns immediately — full nginx apply with large CrowdSec deny lists is slow.
func (h *IDSHandler) applyAsync() {
	if h.CfgApply == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		_ = h.CfgApply(ctx)
	}()
}

func (h *IDSHandler) actorEmail(r *http.Request) string {
	if sess, ok := middleware.SessionFrom(r.Context()); ok {
		return sess.Email
	}
	return ""
}

func (h *IDSHandler) protectedCIDRs(r *http.Request) string {
	v, _ := h.Store.GetSetting(r.Context(), "ids_protected_cidrs")
	if v == "" {
		return nginxcfg.DefaultProtectedCIDRs
	}
	return v
}

func (h *IDSHandler) ListDecisions(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 50
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	items, total, err := h.Store.ListIPPoliciesPage(r.Context(), kind, q, page, perPage)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.IPPolicy{}
	}
	lapiOK := false
	if h.CS != nil && h.CS.Enabled() {
		if err := h.CS.Ping(r.Context()); err == nil {
			lapiOK = true
		}
	}
	trusted, _ := h.Store.GetSetting(r.Context(), "trusted_proxies")
	WriteJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "page": page, "per_page": perPage,
		"lapi_ok": lapiOK, "fail_open": h.FailOpen,
		"bouncer":                 "control-plane-nginx-deny",
		"enforcement":             h.enforcementMode(r),
		"protected_cidrs":         h.protectedCIDRs(r),
		"trusted_proxies_set":     strings.TrimSpace(trusted) != "",
		"real_ip_warning":         strings.TrimSpace(trusted) == "",
		"geoip_available":         false, // optional MaxMind — DEFERRED
	})
}

func (h *IDSHandler) enforcementMode(r *http.Request) string {
	v, _ := h.Store.GetSetting(r.Context(), "ids_enforcement")
	if strings.EqualFold(strings.TrimSpace(v), "passive") {
		return "passive"
	}
	return "active"
}

// GetEnforcement returns IDS active/passive mode (REQ-IDS-019).
func (h *IDSHandler) GetEnforcement(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{
		"enforcement": h.enforcementMode(r),
		"note":        "passive: CrowdSec/DB decisions stay visible; nginx allow/deny not applied",
	})
}

// PutEnforcement sets IDS enforcement and applies nginx (REQ-IDS-019).
func (h *IDSHandler) PutEnforcement(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enforcement string `json:"enforcement"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(body.Enforcement))
	if mode != "active" && mode != "passive" {
		WriteError(w, http.StatusBadRequest, "validation_failed", "enforcement must be active|passive")
		return
	}
	if err := h.Store.SetSetting(r.Context(), "ids_enforcement", mode); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	writeAudit(h.Store, r, "ids.enforcement", "platform_settings", "ids_enforcement", map[string]string{"enforcement": mode})
	h.apply(r)
	WriteJSON(w, http.StatusOK, map[string]any{"enforcement": mode, "applied": true})
}

type banReq struct {
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	TTLHours int    `json:"ttl_hours"`
}

func (h *IDSHandler) CreateBan(w http.ResponseWriter, r *http.Request) {
	h.createPolicy(w, r, "ban")
}

func (h *IDSHandler) ListAllow(w http.ResponseWriter, r *http.Request) {
	h.listKind(w, r, "allow")
}

func (h *IDSHandler) CreateAllow(w http.ResponseWriter, r *http.Request) {
	h.createPolicy(w, r, "allow")
}

func (h *IDSHandler) ListDeny(w http.ResponseWriter, r *http.Request) {
	h.listKind(w, r, "deny")
}

func (h *IDSHandler) CreateDeny(w http.ResponseWriter, r *http.Request) {
	h.createPolicy(w, r, "deny")
}

func (h *IDSHandler) listKind(w http.ResponseWriter, r *http.Request, kind string) {
	items, err := h.Store.ListIPPolicies(r.Context(), kind)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.IPPolicy{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *IDSHandler) createPolicy(w http.ResponseWriter, r *http.Request, kind string) {
	var req banReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	ip := strings.TrimSpace(req.IP)
	if err := nginxcfg.ValidateIPCIDR(ip); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	if kind == "ban" || kind == "deny" {
		if err := nginxcfg.ValidateProtectedBan(ip, h.protectedCIDRs(r)); err != nil {
			WriteError(w, http.StatusForbidden, "protected_ip", err.Error())
			return
		}
	}
	p := models.IPPolicy{
		Kind: kind, IPCIDR: ip, Reason: strings.TrimSpace(req.Reason), Source: "manual",
	}
	if p.Reason == "" {
		p.Reason = kind
	}
	if req.TTLHours > 0 {
		exp := time.Now().UTC().Add(time.Duration(req.TTLHours) * time.Hour)
		p.ExpiresAt = &exp
	}
	if sess, ok := middleware.SessionFrom(r.Context()); ok {
		uid := sess.UserID
		p.CreatedBy = &uid
	}
	created, err := h.Store.CreateIPPolicy(r.Context(), p)
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "could not create policy")
		return
	}
	pid := created.ID
	_ = h.Store.InsertIPPolicyHistory(r.Context(), models.IPPolicyHistory{
		PolicyID: &pid, Action: "create", Kind: created.Kind, IPCIDR: created.IPCIDR,
		Reason: created.Reason, Source: created.Source, ActorEmail: h.actorEmail(r),
	})
	writeAudit(h.Store, r, "ids."+kind+"_create", "ip_policy", created.ID.String(), map[string]string{
		"ip": created.IPCIDR, "reason": created.Reason,
	})
	_, _ = h.Store.InsertSecurityEvent(r.Context(), models.SecurityEvent{
		Source: "crowdsec", RuleID: "manual-" + kind, Message: created.Reason,
		ClientIP: created.IPCIDR, PayloadSummary: kind + " " + created.IPCIDR,
		UniqueID: created.ID.String(),
	})
	h.apply(r)
	WriteJSON(w, http.StatusCreated, created)
}

func (h *IDSHandler) deleteOne(r *http.Request, id uuid.UUID) error {
	existing, err := h.Store.GetIPPolicy(r.Context(), id)
	if err != nil {
		return err
	}
	if err := h.Store.DeleteIPPolicy(r.Context(), id); err != nil {
		return err
	}
	// CrowdSec sync would re-insert within seconds — suppress until LAPI decision expires/gone.
	if existing.Source == "crowdsec" {
		_ = h.Store.SuppressIPPolicy(r.Context(), existing.IPCIDR, existing.ExternalID, "panel-delete")
	}
	pid := existing.ID
	_ = h.Store.InsertIPPolicyHistory(r.Context(), models.IPPolicyHistory{
		PolicyID: &pid, Action: "delete", Kind: existing.Kind, IPCIDR: existing.IPCIDR,
		Reason: existing.Reason, Source: existing.Source, ActorEmail: h.actorEmail(r),
	})
	writeAudit(h.Store, r, "ids.policy_delete", "ip_policy", id.String(), map[string]string{
		"ip": existing.IPCIDR, "kind": existing.Kind,
	})
	return nil
}

func (h *IDSHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if err := h.deleteOne(r, id); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	h.applyAsync()
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted", "apply": "async"})
}

// BulkCreatePolicies creates many IP policies with a shared reason, then applies once (REQ-IDS-018).
func (h *IDSHandler) BulkCreatePolicies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind     string   `json:"kind"`
		Reason   string   `json:"reason"`
		TTLHours int      `json:"ttl_hours"`
		IPs      []string `json:"ips"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	kind := strings.TrimSpace(body.Kind)
	switch kind {
	case "ban", "allow", "deny":
	default:
		WriteError(w, http.StatusBadRequest, "validation_failed", "kind must be ban|allow|deny")
		return
	}
	if len(body.IPs) == 0 {
		WriteError(w, http.StatusBadRequest, "validation_failed", "ips required")
		return
	}
	if len(body.IPs) > 500 {
		WriteError(w, http.StatusBadRequest, "validation_failed", "max 500 ips")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = kind
	}
	var expires *time.Time
	if kind == "ban" && body.TTLHours > 0 {
		exp := time.Now().UTC().Add(time.Duration(body.TTLHours) * time.Hour)
		expires = &exp
	}
	var createdBy *uuid.UUID
	if sess, ok := middleware.SessionFrom(r.Context()); ok {
		uid := sess.UserID
		createdBy = &uid
	}
	created := 0
	skipped := 0
	var errorsOut []string
	seen := map[string]bool{}
	for _, raw := range body.IPs {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		key := strings.ToLower(ip)
		if seen[key] {
			skipped++
			continue
		}
		seen[key] = true
		if err := nginxcfg.ValidateIPCIDR(ip); err != nil {
			errorsOut = append(errorsOut, ip+": "+err.Error())
			continue
		}
		if kind == "ban" || kind == "deny" {
			if err := nginxcfg.ValidateProtectedBan(ip, h.protectedCIDRs(r)); err != nil {
				errorsOut = append(errorsOut, ip+": "+err.Error())
				continue
			}
		}
		p := models.IPPolicy{
			Kind: kind, IPCIDR: ip, Reason: reason, Source: "manual",
			ExpiresAt: expires, CreatedBy: createdBy,
		}
		item, err := h.Store.CreateIPPolicy(r.Context(), p)
		if err != nil {
			skipped++
			continue
		}
		pid := item.ID
		_ = h.Store.InsertIPPolicyHistory(r.Context(), models.IPPolicyHistory{
			PolicyID: &pid, Action: "create", Kind: item.Kind, IPCIDR: item.IPCIDR,
			Reason: item.Reason, Source: item.Source, ActorEmail: h.actorEmail(r),
		})
		created++
	}
	if created > 0 {
		h.applyAsync()
	}
	writeAudit(h.Store, r, "ids.policy_bulk_create", "ip_policy", "", map[string]string{
		"kind": kind, "created": strconv.Itoa(created), "skipped": strconv.Itoa(skipped),
		"errors": strconv.Itoa(len(errorsOut)), "reason": reason,
	})
	if len(errorsOut) > 20 {
		errorsOut = append(errorsOut[:20], "…")
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"created": created, "skipped": skipped, "errors": errorsOut, "apply": "async",
	})
}

// BulkDeletePolicies removes many IP policies then applies nginx once (REQ-IDS-005/008).
func (h *IDSHandler) BulkDeletePolicies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if len(body.IDs) == 0 {
		WriteError(w, http.StatusBadRequest, "validation_failed", "ids required")
		return
	}
	if len(body.IDs) > 500 {
		WriteError(w, http.StatusBadRequest, "validation_failed", "max 500 ids")
		return
	}
	deleted := 0
	missing := 0
	for _, raw := range body.IDs {
		id, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
			return
		}
		err = h.deleteOne(r, id)
		if errors.Is(err, db.ErrNotFound) {
			missing++
			continue
		}
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
			return
		}
		deleted++
	}
	if deleted > 0 {
		h.applyAsync()
	}
	writeAudit(h.Store, r, "ids.policy_bulk_delete", "ip_policy", "", map[string]string{
		"deleted": strconv.Itoa(deleted), "missing": strconv.Itoa(missing),
	})
	WriteJSON(w, http.StatusOK, map[string]any{"deleted": deleted, "missing": missing, "apply": "async"})
}

func (h *IDSHandler) ListHistory(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = 50
	}
	offset := (page - 1) * limit
	items, err := h.Store.ListIPPolicyHistory(r.Context(), limit, offset)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.IPPolicyHistory{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "page": page})
}

func (h *IDSHandler) GetProtected(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"protected_cidrs": h.protectedCIDRs(r)})
}

func (h *IDSHandler) loadDetection(r *http.Request) crowdsec.DetectionSettings {
	s := crowdsec.DefaultDetectionSettings()
	raw, _ := h.Store.GetSetting(r.Context(), "ids_detection")
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	s.Normalize()
	return s
}

func (h *IDSHandler) GetDetection(w http.ResponseWriter, r *http.Request) {
	s := h.loadDetection(r)
	agentOK := h.CS != nil && h.CS.AgentPing(r.Context())
	WriteJSON(w, http.StatusOK, map[string]any{
		"settings": s,
		"agent_ok": agentOK,
		"hints": map[string]string{
			"http_probing_capacity": "Kaç farklı 404/403/400 path sonrası ban (http-probing)",
			"http_crawl_capacity":   "Agresif crawl eşiği (http-crawl-non_statics)",
			"http_bf_capacity":      "Auth brute-force eşiği (http-generic-bf)",
			"ban_duration":          "CrowdSec karar süresi (profiles.yaml)",
		},
	})
}

func (h *IDSHandler) PutDetection(w http.ResponseWriter, r *http.Request) {
	var body crowdsec.DetectionSettings
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if err := body.Validate(); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	body.Normalize()
	files, err := body.RenderOverrideFiles()
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	raw, _ := json.Marshal(body)
	if err := h.Store.SetSetting(r.Context(), "ids_detection", string(raw)); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	// CrowdSec agent writes live scenarios + /nsp-overrides for boot persistence.
	if h.CS != nil {
		if err := h.CS.ApplyDetection(r.Context(), files); err != nil {
			WriteError(w, http.StatusBadGateway, "crowdsec_apply_failed", err.Error())
			return
		}
	}
	writeAudit(h.Store, r, "ids.detection", "platform_settings", "ids_detection", body)
	WriteJSON(w, http.StatusOK, map[string]any{"settings": body, "applied": true})
}

func (h *IDSHandler) PutProtected(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProtectedCIDRs string `json:"protected_cidrs"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	for _, p := range nginxcfg.ParseCIDRList(body.ProtectedCIDRs) {
		if err := nginxcfg.ValidateIPCIDR(p); err != nil {
			WriteError(w, http.StatusBadRequest, "validation_failed", "invalid cidr: "+p)
			return
		}
	}
	if err := h.Store.SetSetting(r.Context(), "ids_protected_cidrs", strings.TrimSpace(body.ProtectedCIDRs)); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	writeAudit(h.Store, r, "ids.protected_cidrs", "platform_settings", "ids_protected_cidrs", nil)
	WriteJSON(w, http.StatusOK, map[string]string{"protected_cidrs": strings.TrimSpace(body.ProtectedCIDRs)})
}

// UnifiedEvents lists WAF+IDS events with optional source filter (REQ-OBS-003).
func (h *IDSHandler) UnifiedEvents(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	limit, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit
	items, err := h.Store.ListSecurityEventsFiltered(r.Context(), source, limit, offset)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.SecurityEvent{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "page": page, "source": source})
}
