package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func DecodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeAudit(store *db.Store, r *http.Request, action, resourceType, resourceID string, details any) {
	sess, ok := middleware.SessionFrom(r.Context())
	b, _ := json.Marshal(details)
	if len(b) == 0 {
		b = []byte(`{}`)
	}
	a := models.AuditLog{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		RequestID:    middleware.RequestIDFrom(r.Context()),
		IP:           middleware.ClientIP(r),
		Details:      b,
	}
	if ok {
		uid := sess.UserID
		a.ActorUserID = &uid
		a.ActorEmail = sess.Email
	}
	_ = store.InsertAudit(r.Context(), a)
}
