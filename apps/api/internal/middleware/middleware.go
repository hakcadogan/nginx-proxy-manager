package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/auth"
	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/metrics"
	"github.com/nginx-proxy-waf/api/internal/models"
)

var errUnauthorized = errors.New("unauthorized")

type ctxKey string

const (
	CtxRequestID ctxKey = "request_id"
	CtxSession   ctxKey = "session"
	CtxAuthMode  ctxKey = "auth_mode" // cookie | token
	CtxTokenScopes ctxKey = "token_scopes"
)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), CtxRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusWriter{ResponseWriter: w, code: 200}
			next.ServeHTTP(ww, r)
			rid, _ := r.Context().Value(CtxRequestID).(string)
			log.Info("request",
				"request_id", rid,
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.code,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	code int
	buf  *bytes.Buffer
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.buf != nil {
		_, _ = w.buf.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

type Auth struct {
	Sessions *auth.SessionStore
	Store    *db.Store
	Cfg      config.Config
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authz := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			raw := strings.TrimSpace(authz[7:])
			sess, scopes, err := a.authenticateToken(r.Context(), raw)
			if err != nil {
				_ = errUnauthorized
				writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid api token")
				return
			}
			ctx := context.WithValue(r.Context(), CtxSession, sess)
			ctx = context.WithValue(ctx, CtxAuthMode, "token")
			ctx = context.WithValue(ctx, CtxTokenScopes, scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		c, err := r.Cookie(a.Cfg.CookieName)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		sess, err := a.Sessions.Get(r.Context(), c.Value)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid session")
			return
		}
		if isMutating(r.Method) {
			csrf := r.Header.Get("X-CSRF-Token")
			if csrf == "" || csrf != sess.CSRFToken {
				writeErr(w, http.StatusForbidden, "csrf_failed", "CSRF token missing or invalid")
				return
			}
		}
		ctx := context.WithValue(r.Context(), CtxSession, sess)
		ctx = context.WithValue(ctx, CtxAuthMode, "cookie")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Auth) authenticateToken(ctx context.Context, raw string) (models.Session, []string, error) {
	// nsp_<prefix>_<secret>
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != "nsp" || parts[1] == "" || parts[2] == "" {
		return models.Session{}, nil, errUnauthorized
	}
	prefix := parts[1]
	hash := db.HashAPIToken(raw)
	tok, u, err := a.Store.LookupAPIToken(ctx, prefix, hash)
	if err != nil {
		return models.Session{}, nil, err
	}
	return models.Session{
		ID:        "token:" + tok.ID.String(),
		UserID:    u.ID,
		Email:     u.Email,
		Role:      u.Role,
		CSRFToken: "",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, tok.Scopes, nil
}

func Require(perm auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := SessionFrom(r.Context())
			if !ok {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			if scopes, ok := r.Context().Value(CtxTokenScopes).([]string); ok && scopes != nil {
				allowed := false
				for _, s := range scopes {
					if auth.Permission(s) == perm {
						allowed = true
						break
					}
				}
				if !allowed {
					writeErr(w, http.StatusForbidden, "forbidden", "token scope insufficient")
					return
				}
			} else if !auth.HasPermission(sess.Role, perm) {
				writeErr(w, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func SessionFrom(ctx context.Context) (models.Session, bool) {
	s, ok := ctx.Value(CtxSession).(models.Session)
	return s, ok
}

func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(CtxRequestID).(string)
	return s
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func writeErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func CORS(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			o := origin
			if o == "" {
				o = "*"
			}
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Request-ID, Authorization, Idempotency-Key")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,DELETE,OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
}

// APIRateLimit — simple per-IP sliding window for control plane (REQ-API-013).
type APIRateLimit struct {
	mu      sync.Mutex
	hits    map[string][]time.Time
	Limit   int
	Window  time.Duration
}

func NewAPIRateLimit(limit int, window time.Duration) *APIRateLimit {
	return &APIRateLimit{hits: map[string][]time.Time{}, Limit: limit, Window: window}
}

func (rl *APIRateLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		now := time.Now()
		rl.mu.Lock()
		cut := now.Add(-rl.Window)
		arr := rl.hits[ip]
		filtered := arr[:0]
		for _, t := range arr {
			if t.After(cut) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) >= rl.Limit {
			rl.hits[ip] = filtered
			rl.mu.Unlock()
			metrics.RateLimitHits.Inc()
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		filtered = append(filtered, now)
		rl.hits[ip] = filtered
		rl.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// Idempotency caches responses for Idempotency-Key on mutating config paths (REQ-API-012).
func Idempotency(store *db.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Idempotency-Key")
			if key == "" || !isMutating(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			sess, ok := SessionFrom(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if status, body, found, err := store.GetIdempotency(r.Context(), sess.UserID, key, r.Method, r.URL.Path); err == nil && found {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(status)
				_, _ = w.Write(body)
				return
			}
			buf := &bytes.Buffer{}
			ww := &statusWriter{ResponseWriter: w, code: 200, buf: buf}
			next.ServeHTTP(ww, r)
			_ = store.SaveIdempotency(r.Context(), sess.UserID, key, r.Method, r.URL.Path, ww.code, buf.Bytes())
		})
	}
}
