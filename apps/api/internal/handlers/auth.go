package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/nginx-proxy-waf/api/internal/auth"
	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/metrics"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
)

type AuthHandler struct {
	Store    *db.Store
	Sessions *auth.SessionStore
	Cfg      config.Config
}

type bootstrapReq struct {
	Token    string `json:"token"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
}

type mfaLoginReq struct {
	PreAuthToken string `json:"pre_auth_token"`
	TOTP         string `json:"totp"`
}

func (h *AuthHandler) BootstrapStatus(w http.ResponseWriter, r *http.Request) {
	n, err := h.Store.CountUsers(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "database error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"bootstrap_required": n == 0})
}

func (h *AuthHandler) Bootstrap(w http.ResponseWriter, r *http.Request) {
	n, err := h.Store.CountUsers(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "database error")
		return
	}
	if n > 0 {
		WriteError(w, http.StatusConflict, "conflict", "bootstrap already completed")
		return
	}
	var req bootstrapReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if req.Token == "" || req.Token != h.Cfg.BootstrapToken {
		WriteError(w, http.StatusForbidden, "forbidden", "invalid bootstrap token")
		return
	}
	if !validEmail(req.Email) {
		WriteError(w, http.StatusBadRequest, "validation_failed", "email required")
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "hash failed")
		return
	}
	u, err := h.Store.CreateUser(r.Context(), req.Email, hash, models.RoleAdmin)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "create user failed")
		return
	}
	writeAudit(h.Store, r, "user.bootstrap", "user", u.ID.String(), map[string]string{"email": u.Email})
	WriteJSON(w, http.StatusCreated, map[string]any{"user": publicUser(u)})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	u, err := h.Store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		metrics.LoginFailures.Inc()
		WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
		return
	}
	if h.Store.IsLocked(u) {
		WriteError(w, http.StatusLocked, "account_locked", "account temporarily locked")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		metrics.LoginFailures.Inc()
		nu, _ := h.Store.RecordFailedLogin(r.Context(), u.ID)
		if h.Store.IsLocked(nu) {
			metrics.LoginLockouts.Inc()
		}
		writeAudit(h.Store, r, "auth.login_failed", "user", u.ID.String(), map[string]string{"email": u.Email})
		WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
		return
	}
	if u.MFAEnabled {
		if req.TOTP != "" {
			if !auth.ValidateTOTP(u.MFASecret, req.TOTP) {
				metrics.LoginFailures.Inc()
				WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid MFA code")
				return
			}
		} else {
			pre, err := h.Sessions.SavePreAuth(r.Context(), u.ID, u.Email, 5*time.Minute)
			if err != nil {
				WriteError(w, http.StatusInternalServerError, "internal", "preauth failed")
				return
			}
			WriteJSON(w, http.StatusOK, map[string]any{
				"mfa_required":    true,
				"pre_auth_token":  pre.Token,
				"expires_at":      pre.ExpiresAt.UTC().Format(time.RFC3339),
			})
			return
		}
	}
	_ = h.Store.ClearFailedLogin(r.Context(), u.ID)
	h.issueSession(w, r, u)
}

func (h *AuthHandler) MFALogin(w http.ResponseWriter, r *http.Request) {
	var req mfaLoginReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	pre, err := h.Sessions.ConsumePreAuth(r.Context(), req.PreAuthToken)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired pre-auth")
		return
	}
	u, err := h.Store.GetUserByID(r.Context(), pre.UserID)
	if err != nil || !u.MFAEnabled {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "MFA not available")
		return
	}
	if !auth.ValidateTOTP(u.MFASecret, req.TOTP) {
		metrics.LoginFailures.Inc()
		WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid MFA code")
		return
	}
	_ = h.Store.ClearFailedLogin(r.Context(), u.ID)
	h.issueSession(w, r, u)
}

func (h *AuthHandler) issueSession(w http.ResponseWriter, r *http.Request, u models.User) {
	sess, err := auth.NewSession(u, h.Cfg.SessionTTL)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "session create failed")
		return
	}
	if err := h.Sessions.Save(r.Context(), sess); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "session store failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.Cfg.CookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     h.Cfg.CSRFCookieName,
		Value:    sess.CSRFToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   h.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	writeAudit(h.Store, r, "auth.login", "user", u.ID.String(), map[string]string{"email": u.Email})
	WriteJSON(w, http.StatusOK, map[string]any{
		"user":       publicUser(u),
		"csrf_token": sess.CSRFToken,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(h.Cfg.CookieName); err == nil {
		_ = h.Sessions.Delete(r.Context(), c.Value)
	}
	expired := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{Name: h.Cfg.CookieName, Value: "", Path: "/", Expires: expired, MaxAge: -1, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: h.Cfg.CSRFCookieName, Value: "", Path: "/", Expires: expired, MaxAge: -1})
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	u, err := h.Store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "user not found")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"user":       publicUser(u),
		"csrf_token": sess.CSRFToken,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *AuthHandler) MFAEnroll(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	secret, url, qr, err := auth.GenerateMFASecret(sess.Email, auth.MFAIssuer())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "MFA enroll failed")
		return
	}
	if err := h.Store.SetMFASecret(r.Context(), sess.UserID, secret); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "store secret failed")
		return
	}
	writeAudit(h.Store, r, "auth.mfa_enroll", "user", sess.UserID.String(), map[string]string{})
	WriteJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_url": url,
		"qr_png_b64":  qr,
	})
}

type mfaConfirmReq struct {
	TOTP string `json:"totp"`
}

func (h *AuthHandler) MFAConfirm(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var req mfaConfirmReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	u, err := h.Store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "user lookup failed")
		return
	}
	if !auth.ValidateTOTP(u.MFASecret, req.TOTP) {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid TOTP")
		return
	}
	if err := h.Store.EnableMFA(r.Context(), sess.UserID); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "enable failed")
		return
	}
	writeAudit(h.Store, r, "auth.mfa_enable", "user", sess.UserID.String(), map[string]string{})
	WriteJSON(w, http.StatusOK, map[string]any{"mfa_enabled": true})
}

func (h *AuthHandler) MFADisable(w http.ResponseWriter, r *http.Request) {
	sess, ok := middleware.SessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var req mfaConfirmReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	u, err := h.Store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "user lookup failed")
		return
	}
	if u.MFAEnabled && !auth.ValidateTOTP(u.MFASecret, req.TOTP) {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid TOTP")
		return
	}
	if err := h.Store.DisableMFA(r.Context(), sess.UserID); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "disable failed")
		return
	}
	writeAudit(h.Store, r, "auth.mfa_disable", "user", sess.UserID.String(), map[string]string{})
	WriteJSON(w, http.StatusOK, map[string]any{"mfa_enabled": false})
}

func publicUser(u models.User) map[string]any {
	out := map[string]any{
		"id":          u.ID,
		"email":       u.Email,
		"role":        u.Role,
		"mfa_enabled": u.MFAEnabled,
		"created_at":  u.CreatedAt,
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		out["locked_until"] = u.LockedUntil.UTC().Format(time.RFC3339)
	}
	return out
}

func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	return strings.Contains(s, "@") && len(s) >= 5 && len(s) <= 254
}
