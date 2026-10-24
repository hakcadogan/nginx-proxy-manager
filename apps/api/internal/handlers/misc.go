package handlers

import (
	"net/http"
	"strconv"

	"github.com/nginx-proxy-waf/api/internal/db"
)

type MiscHandler struct {
	Store      *db.Store
	AppVersion string
}

func (h *MiscHandler) Health(w http.ResponseWriter, r *http.Request) {
	if err := h.Store.Pool.Ping(r.Context()); err != nil {
		WriteError(w, http.StatusServiceUnavailable, "unhealthy", "database unavailable")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *MiscHandler) Version(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"version": h.AppVersion, "phase": "P01"})
}

func (h *MiscHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = 50
	}
	offset := (page - 1) * limit
	items, err := h.Store.ListAudit(r.Context(), limit, offset)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "page": page})
}
