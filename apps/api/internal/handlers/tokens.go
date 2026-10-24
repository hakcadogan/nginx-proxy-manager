package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/auth"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
)

// TokenHandler — scoped API tokens (REQ-AUTH-008).
type TokenHandler struct {
	Store *db.Store
}

type createTokenReq struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresIn string   `json:"expires_in,omitempty"` // e.g. 720h
}

func (h *TokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var req createTokenReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "validation_failed", "name required")
		return
	}
	scopes, err := normalizeScopes(req.Scopes, sess.Role)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	var expires *time.Time
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 {
			WriteError(w, http.StatusBadRequest, "validation_failed", "invalid expires_in")
			return
		}
		t := time.Now().Add(d)
		expires = &t
	}
	secret, err := auth.RandomToken(32)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "token generate failed")
		return
	}
	prefix := secret[:8]
	raw := "nsp_" + prefix + "_" + secret
	hash := db.HashAPIToken(raw)
	tok, err := h.Store.CreateAPIToken(r.Context(), sess.UserID, req.Name, prefix, hash, scopes, expires)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "create failed")
		return
	}
	tok.Token = raw
	writeAudit(h.Store, r, "token.create", "api_token", tok.ID.String(), map[string]string{"name": tok.Name})
	WriteJSON(w, http.StatusCreated, map[string]any{"token": tok})
}

func (h *TokenHandler) List(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	items, err := h.Store.ListAPITokens(r.Context(), sess.UserID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *TokenHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if err := h.Store.DeleteAPIToken(r.Context(), sess.UserID, id); err != nil {
		WriteError(w, http.StatusNotFound, "not_found", "token not found")
		return
	}
	writeAudit(h.Store, r, "token.delete", "api_token", id.String(), map[string]string{})
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func normalizeScopes(scopes []string, role models.Role) ([]string, error) {
	if len(scopes) == 0 {
		scopes = []string{"hosts:read", "config:read"}
	}
	out := make([]string, 0, len(scopes))
	seen := map[string]bool{}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		perm := auth.Permission(s)
		if !auth.HasPermission(role, perm) {
			return nil, fmt.Errorf("scope %q not allowed for role", s)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}
