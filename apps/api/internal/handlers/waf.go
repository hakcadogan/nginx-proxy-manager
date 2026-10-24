package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/nginxcfg"
)

type WAFHandler struct {
	Store      *db.Store
	ModsecDir  string // /var/lib/nsp/modsec
	CRSVersion string
	ApplyHook  func(r *http.Request) // optional — UI also calls config/apply
}

const (
	settingUAAllowlist      = "waf_ua_allowlist"
	settingModSecGlobal     = "waf_modsec_settings"
	settingCustomRules      = "waf_custom_rules"
	settingDisabledCRSRules = "waf_disabled_crs_rules"
)

func (h *WAFHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.ListWAFPolicies(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "crs_version": h.crsVersion()})
}

func (h *WAFHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	p, err := h.Store.GetWAFPolicy(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	WriteJSON(w, http.StatusOK, p)
}

func (h *WAFHandler) PatchPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	existing, err := h.Store.GetWAFPolicy(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	var patch models.WAFPolicy
	if err := DecodeJSON(r, &patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	patch.ID = existing.ID
	if patch.Name == "" {
		patch.Name = existing.Name
	}
	if patch.EngineMode == "" {
		patch.EngineMode = existing.EngineMode
	}
	if patch.ParanoiaLevel == 0 {
		patch.ParanoiaLevel = existing.ParanoiaLevel
	}
	if patch.InboundAnomalyScoreThreshold == 0 {
		patch.InboundAnomalyScoreThreshold = existing.InboundAnomalyScoreThreshold
	}
	if patch.OutboundAnomalyScoreThreshold == 0 {
		patch.OutboundAnomalyScoreThreshold = existing.OutboundAnomalyScoreThreshold
	}
	// Preserve enabled unless explicitly sent — DecodeJSON zeros bool; use existing when mode alone patched.
	// Callers should send enabled; default keep existing when engine_mode unchanged path from UI always sends it.
	if !patch.Enabled && existing.Enabled && patch.EngineMode == existing.EngineMode && patch.ParanoiaLevel == existing.ParanoiaLevel {
		// ambiguous; prefer existing.Enabled when only thresholds change — UI always sends enabled.
	}
	if err := nginxcfg.ValidateWAFPolicy(patch); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	updated, err := h.Store.UpdateWAFPolicy(r.Context(), patch)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "update failed")
		return
	}
	writeAudit(h.Store, r, "waf.policy_update", "waf_policy", updated.ID.String(), map[string]any{
		"engine_mode": updated.EngineMode, "paranoia_level": updated.ParanoiaLevel, "enabled": updated.Enabled,
		"inbound_anomaly_score_threshold": updated.InboundAnomalyScoreThreshold,
	})
	WriteJSON(w, http.StatusOK, updated)
}

// UpsertHostPolicy creates/updates a per-host WAF policy (REQ-WAF-005).
func (h *WAFHandler) UpsertHostPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HostID                         uuid.UUID `json:"host_id"`
		Enabled                        bool      `json:"enabled"`
		EngineMode                     string    `json:"engine_mode"`
		ParanoiaLevel                  int       `json:"paranoia_level"`
		InboundAnomalyScoreThreshold   int       `json:"inbound_anomaly_score_threshold"`
		OutboundAnomalyScoreThreshold  int       `json:"outbound_anomaly_score_threshold"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if _, err := h.Store.GetHost(r.Context(), body.HostID); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "host not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "host lookup failed")
		return
	}
	p := models.WAFPolicy{
		Enabled: body.Enabled, EngineMode: body.EngineMode, ParanoiaLevel: body.ParanoiaLevel,
		InboundAnomalyScoreThreshold: body.InboundAnomalyScoreThreshold,
		OutboundAnomalyScoreThreshold: body.OutboundAnomalyScoreThreshold,
		AuditRelevantOnly: true,
	}
	if p.EngineMode == "" {
		p.EngineMode = "DetectionOnly"
	}
	if p.ParanoiaLevel == 0 {
		p.ParanoiaLevel = 1
	}
	if err := nginxcfg.ValidateWAFPolicy(p); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	updated, err := h.Store.UpsertHostWAFPolicy(r.Context(), body.HostID, p)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "upsert failed")
		return
	}
	writeAudit(h.Store, r, "waf.host_policy_upsert", "waf_policy", updated.ID.String(), map[string]any{
		"host_id": body.HostID.String(), "engine_mode": updated.EngineMode,
	})
	WriteJSON(w, http.StatusOK, updated)
}

func (h *WAFHandler) ListExceptions(w http.ResponseWriter, r *http.Request) {
	var pid *uuid.UUID
	if s := r.URL.Query().Get("policy_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "validation_failed", "invalid policy_id")
			return
		}
		pid = &id
	}
	items, err := h.Store.ListWAFExceptions(r.Context(), pid)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.WAFException{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *WAFHandler) CreateException(w http.ResponseWriter, r *http.Request) {
	var e models.WAFException
	if err := DecodeJSON(r, &e); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	e.RuleID = strings.TrimSpace(e.RuleID)
	e.Enabled = true
	if err := nginxcfg.ValidateWAFException(e); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	if _, err := h.Store.GetWAFPolicy(r.Context(), e.PolicyID); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	if sess, ok := middleware.SessionFrom(r.Context()); ok {
		uid := sess.UserID
		e.CreatedBy = &uid
	}
	if e.HostID != nil {
		if _, err := h.Store.GetHost(r.Context(), *e.HostID); errors.Is(err, db.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "host not found")
			return
		} else if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal", "host lookup failed")
			return
		}
	}
	created, err := h.Store.CreateWAFException(r.Context(), e)
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "could not create exception")
		return
	}
	writeAudit(h.Store, r, "waf.exception_create", "waf_exception", created.ID.String(), map[string]any{
		"rule_id": created.RuleID, "path_prefix": created.PathPrefix, "argument": created.Argument,
		"host_id": created.HostID, "global_disable": nginxcfg.ExceptionIsGlobalDisable(created),
	})
	// Overlay is only live after nginx apply (ModSec Include reload).
	if h.ApplyHook != nil {
		h.ApplyHook(r)
	}
	WriteJSON(w, http.StatusCreated, created)
}

func (h *WAFHandler) DeleteException(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if err := h.Store.DeleteWAFException(r.Context(), id); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "exception not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	writeAudit(h.Store, r, "waf.exception_delete", "waf_exception", id.String(), nil)
	if h.ApplyHook != nil {
		h.ApplyHook(r)
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *WAFHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit
	items, err := h.Store.SearchSecurityEvents(r.Context(), db.SecurityEventFilter{
		Source: r.URL.Query().Get("source"),
		Q:      r.URL.Query().Get("q"),
		RuleID: r.URL.Query().Get("rule_id"),
		Domain: r.URL.Query().Get("domain"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.SecurityEvent{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "page": page})
}

// AttackReport aggregates events by CRS attack category (REQ-WAF-014).
func (h *WAFHandler) AttackReport(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.AggregateSecurityEventsByRule(r.Context(), "waf", 100)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "report failed")
		return
	}
	byType := map[string]int{}
	top := []map[string]any{}
	for _, row := range rows {
		cat := nginxcfg.ClassifyCRSAttackType(row.RuleID)
		byType[cat] += row.Count
		item := map[string]any{
			"rule_id": row.RuleID, "count": row.Count, "attack_type": cat,
			"last_client_ip": row.LastClientIP,
		}
		if !row.LastSeen.IsZero() {
			item["last_seen"] = row.LastSeen.UTC().Format(time.RFC3339)
		}
		top = append(top, item)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"by_attack_type": byType,
		"top_rules":      top,
		"crs_version":    h.crsVersion(),
		"note":           "Categories derived from OWASP CRS rule ID prefixes (920=protocol, 930=LFI, 941=XSS, 942=SQLi, …)",
	})
}

func (h *WAFHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	ev, err := h.Store.GetSecurityEvent(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "event not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	WriteJSON(w, http.StatusOK, ev)
}

// SuggestException builds a tuning suggestion from an event (REQ-WAF-011).
func (h *WAFHandler) SuggestException(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	ev, err := h.Store.GetSecurityEvent(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "event not found")
		return
	}
	global, err := h.Store.GetGlobalWAFPolicy(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "policy missing")
		return
	}
	path := ev.URI
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	sug := models.WAFException{
		PolicyID:   global.ID,
		HostID:     ev.HostID,
		RuleID:     ev.RuleID,
		PathPrefix: path,
		Reason:     "tuning from event " + strconv.FormatInt(ev.ID, 10),
		Enabled:    true,
	}
	if sug.HostID == nil && ev.Domain != "" {
		if id, err := h.Store.FindHostIDByDomain(r.Context(), ev.Domain); err == nil {
			sug.HostID = &id
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"suggestion": sug})
}

func (h *WAFHandler) crsVersion() string {
	if h.CRSVersion != "" {
		return h.CRSVersion
	}
	candidates := []string{
		filepath.Join(h.modsecDir(), "crs-version.txt"),
		strings.TrimSpace(os.Getenv("MODSEC_CRS_VERSION_FILE")),
		"/etc/nginx/modsec/crs-version.txt",
	}
	var raw string
	for _, p := range candidates {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		raw = strings.TrimSpace(string(b))
		if raw != "" {
			break
		}
	}
	if raw == "" {
		return "unknown"
	}
	return formatCRSVersionLabel(raw)
}

// formatCRSVersionLabel turns CRS=4.20.0 / MODSECURITY=… into a short UI label.
func formatCRSVersionLabel(raw string) string {
	var crs, modsec string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "CRS=") {
			crs = strings.TrimPrefix(line, "CRS=")
			continue
		}
		if strings.HasPrefix(line, "MODSECURITY=") {
			modsec = strings.TrimPrefix(line, "MODSECURITY=")
			continue
		}
		// legacy single-line / free text
		if crs == "" && !strings.Contains(line, "=") {
			crs = line
		}
	}
	switch {
	case crs != "" && modsec != "":
		return crs + " · ModSec " + modsec
	case crs != "":
		return crs
	case modsec != "":
		return "ModSec " + modsec
	default:
		return strings.ReplaceAll(strings.TrimSpace(raw), "\n", " · ")
	}
}

func (h *WAFHandler) modsecDir() string {
	if h.ModsecDir != "" {
		return h.ModsecDir
	}
	return "/var/lib/nsp/modsec"
}

func WriteWAFOverlay(dir string, content string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "overlay.conf")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func WriteUAAllowlistFile(dir string, patterns []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "ua-allowlist.txt")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(nginxcfg.FormatUAAllowlistFile(patterns)), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parseUAAllowlistSetting(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var patterns []string
	if err := json.Unmarshal([]byte(raw), &patterns); err == nil {
		return nginxcfg.NormalizeUAAllowlist(patterns)
	}
	// legacy / textarea: one pattern per line
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		lines = append(lines, line)
	}
	return nginxcfg.NormalizeUAAllowlist(lines)
}

func (h *WAFHandler) GetUAAllowlist(w http.ResponseWriter, r *http.Request) {
	raw, _ := h.Store.GetSetting(r.Context(), settingUAAllowlist)
	patterns := parseUAAllowlistSetting(raw)
	if patterns == nil {
		patterns = []string{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"patterns": patterns,
		"presets":  nginxcfg.DefaultUAAllowlistPresets,
		"hint":     "Substring match against User-Agent; skips NSP bad-bot rule only (not CrowdSec IP bans).",
	})
}

func loadModSecSettings(store *db.Store, r *http.Request) nginxcfg.ModSecGlobalSettings {
	s := nginxcfg.DefaultModSecGlobalSettings()
	raw, _ := store.GetSetting(r.Context(), settingModSecGlobal)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	s.Normalize()
	return s
}

func loadCustomRules(store *db.Store, r *http.Request) nginxcfg.CustomRulesBundle {
	b := nginxcfg.CustomRulesBundle{Hosts: map[string]string{}}
	raw, _ := store.GetSetting(r.Context(), settingCustomRules)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &b)
	}
	if b.Hosts == nil {
		b.Hosts = map[string]string{}
	}
	return b
}

func (h *WAFHandler) GetModSecSettings(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{
		"settings": loadModSecSettings(h.Store, r),
		"note":     "SecRuleEngine is controlled by WAF engine mode (DetectionOnly/On/Off), not this form.",
	})
}

func (h *WAFHandler) PutModSecSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Settings nginxcfg.ModSecGlobalSettings `json:"settings"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if err := body.Settings.Validate(); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	body.Settings.Normalize()
	raw, _ := json.Marshal(body.Settings)
	if err := h.Store.SetSetting(r.Context(), settingModSecGlobal, string(raw)); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	writeAudit(h.Store, r, "waf.modsec_settings", "platform_settings", settingModSecGlobal, body.Settings)
	if h.ApplyHook != nil {
		h.ApplyHook(r)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"settings": body.Settings, "saved": true})
}

func (h *WAFHandler) GetCustomRules(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, loadCustomRules(h.Store, r))
}

func (h *WAFHandler) PutCustomRules(w http.ResponseWriter, r *http.Request) {
	var body nginxcfg.CustomRulesBundle
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if body.Hosts == nil {
		body.Hosts = map[string]string{}
	}
	if err := nginxcfg.ValidateCustomRulesText(body.Global); err != nil && strings.TrimSpace(body.Global) != "" {
		WriteError(w, http.StatusBadRequest, "validation_failed", "global: "+err.Error())
		return
	}
	// Resolve host domains for validation
	domains := map[string]string{}
	hosts, _ := h.Store.ListAllActiveHosts(r.Context())
	for _, ho := range hosts {
		domains[ho.ID.String()] = ho.PrimaryDomain
	}
	cleanHosts := map[string]string{}
	for id, text := range body.Hosts {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if _, ok := domains[id]; !ok {
			WriteError(w, http.StatusBadRequest, "validation_failed", "unknown host_id: "+id)
			return
		}
		if err := nginxcfg.ValidateCustomRulesText(text); err != nil {
			WriteError(w, http.StatusBadRequest, "validation_failed", "host: "+err.Error())
			return
		}
		cleanHosts[id] = text
	}
	body.Hosts = cleanHosts
	if _, err := nginxcfg.RenderCustomRules(body, domains); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	raw, _ := json.Marshal(body)
	if err := h.Store.SetSetting(r.Context(), settingCustomRules, string(raw)); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	writeAudit(h.Store, r, "waf.custom_rules", "platform_settings", settingCustomRules, map[string]any{
		"global_bytes": len(body.Global), "hosts": len(body.Hosts),
	})
	if h.ApplyHook != nil {
		h.ApplyHook(r)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"global": body.Global, "hosts": body.Hosts, "saved": true})
}

func (h *WAFHandler) PutUAAllowlist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Patterns []string `json:"patterns"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if err := nginxcfg.ValidateUAAllowlistPatterns(body.Patterns); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	patterns := nginxcfg.NormalizeUAAllowlist(body.Patterns)
	raw, _ := json.Marshal(patterns)
	if err := h.Store.SetSetting(r.Context(), settingUAAllowlist, string(raw)); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	if err := WriteUAAllowlistFile(h.modsecDir(), patterns); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "write allowlist file failed")
		return
	}
	writeAudit(h.Store, r, "waf.ua_allowlist", "platform_settings", settingUAAllowlist, map[string]any{
		"count": len(patterns),
	})
	if h.ApplyHook != nil {
		h.ApplyHook(r)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"patterns": patterns, "saved": true})
}

func (h *WAFHandler) loadDisabledCRSRules(r *http.Request) []string {
	var ids []string
	if raw, _ := h.Store.GetSetting(r.Context(), settingDisabledCRSRules); raw != "" {
		_ = json.Unmarshal([]byte(raw), &ids)
	}
	ids, _ = nginxcfg.NormalizeDisabledRuleIDs(ids)
	return ids
}

// ListCRSRules returns the CRS/NSP rule catalog with enabled flags (REQ-WAF-007).
func (h *WAFHandler) ListCRSRules(w http.ResponseWriter, r *http.Request) {
	catalog, err := nginxcfg.LoadCRSRulesCatalog(h.modsecDir())
	if err != nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "CRS rule catalog missing — restart nginx to sync catalog")
		return
	}
	disabled := h.loadDisabledCRSRules(r)
	disabledSet := nginxcfg.DisabledRuleSet(disabled)
	paranoia, _ := strconv.Atoi(r.URL.Query().Get("paranoia"))
	filtered := nginxcfg.FilterCRSRules(
		catalog, disabledSet,
		r.URL.Query().Get("q"),
		r.URL.Query().Get("category"),
		r.URL.Query().Get("enabled"),
		paranoia,
	)
	limit, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	total := len(filtered)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	pageItems := filtered[start:end]
	out := make([]map[string]any, 0, len(pageItems))
	cats := map[string]int{}
	for _, it := range catalog {
		cats[it.Category]++
	}
	for _, it := range pageItems {
		out = append(out, map[string]any{
			"id": it.ID, "msg": it.Msg, "file": it.File,
			"paranoia": it.Paranoia, "category": it.Category, "phase": it.Phase,
			"enabled": !disabledSet[it.ID],
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":           out,
		"total":           total,
		"page":            page,
		"per_page":        limit,
		"disabled_count":  len(disabled),
		"catalog_count":   len(catalog),
		"categories":      cats,
		"crs_version":     h.crsVersion(),
	})
}

// PatchCRSRule enables or disables a CRS/NSP rule globally via SecRuleRemoveById (REQ-WAF-007).
func (h *WAFHandler) PatchCRSRule(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.PathValue("id"))
	if !nginxcfg.RuleIDValid(ruleID) {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid rule id")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := DecodeJSON(r, &body); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	catalog, err := nginxcfg.LoadCRSRulesCatalog(h.modsecDir())
	if err == nil {
		known := false
		for _, it := range catalog {
			if it.ID == ruleID {
				known = true
				break
			}
		}
		if !known {
			WriteError(w, http.StatusNotFound, "not_found", "rule not in catalog")
			return
		}
	}
	disabled := h.loadDisabledCRSRules(r)
	set := nginxcfg.DisabledRuleSet(disabled)
	if body.Enabled {
		delete(set, ruleID)
	} else {
		set[ruleID] = true
	}
	next := make([]string, 0, len(set))
	for id := range set {
		next = append(next, id)
	}
	next, err = nginxcfg.NormalizeDisabledRuleIDs(next)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	raw, _ := json.Marshal(next)
	if err := h.Store.SetSetting(r.Context(), settingDisabledCRSRules, string(raw)); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "save failed")
		return
	}
	writeAudit(h.Store, r, "waf.crs_rule_toggle", "platform_settings", settingDisabledCRSRules, map[string]any{
		"rule_id": ruleID, "enabled": body.Enabled,
	})
	if h.ApplyHook != nil {
		h.ApplyHook(r)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"id": ruleID, "enabled": body.Enabled, "disabled_count": len(next),
	})
}
