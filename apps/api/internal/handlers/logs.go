package handlers

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/logrotate"
)

// LogsHandler — file log rotation under /data/logs (REQ-OBS-006).
type LogsHandler struct {
	Store  *db.Store
	Cfg    config.Config
	Reopen func(ctx context.Context) error
	LogDir string
}

func (h *LogsHandler) logsRoot() string {
	if h.LogDir != "" {
		return h.LogDir
	}
	if v := os.Getenv("LOGS_DIR"); v != "" {
		return v
	}
	return "/data/logs"
}

func (h *LogsHandler) settings(ctx context.Context) (enabled bool, maxMB, keep int) {
	enabled = true
	maxMB, keep = 100, 7
	if v, _ := h.Store.GetSetting(ctx, "log_rotate_enabled"); v == "false" {
		enabled = false
	}
	if v, _ := h.Store.GetSetting(ctx, "log_rotate_max_mb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxMB = n
		}
	}
	if v, _ := h.Store.GetSetting(ctx, "log_rotate_keep"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			keep = n
		}
	}
	return
}

// RotateNow runs size-based rotation and nginx reopen (REQ-OBS-006).
func (h *LogsHandler) RotateNow(w http.ResponseWriter, r *http.Request) {
	enabled, maxMB, keep := h.settings(r.Context())
	force := r.URL.Query().Get("force") == "1"
	if !enabled && !force {
		WriteJSON(w, http.StatusOK, map[string]any{"rotated": []string{}, "skipped": "disabled"})
		return
	}
	rotated, err := logrotate.RotateTree(h.logsRoot(), int64(maxMB)*1024*1024, keep)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if len(rotated) > 0 && h.Reopen != nil {
		if err := h.Reopen(r.Context()); err != nil {
			WriteError(w, http.StatusBadGateway, "reopen_failed", err.Error())
			return
		}
	}
	writeAudit(h.Store, r, "logs.rotate", "platform", "", map[string]any{"rotated": rotated, "max_mb": maxMB, "keep": keep})
	WriteJSON(w, http.StatusOK, map[string]any{"rotated": rotated, "count": len(rotated)})
}

// RunOnce is used by the background worker.
func (h *LogsHandler) RunOnce(ctx context.Context) (int, error) {
	enabled, maxMB, keep := h.settings(ctx)
	if !enabled {
		return 0, nil
	}
	rotated, err := logrotate.RotateTree(h.logsRoot(), int64(maxMB)*1024*1024, keep)
	if err != nil {
		return 0, err
	}
	if len(rotated) > 0 && h.Reopen != nil {
		if err := h.Reopen(ctx); err != nil {
			return len(rotated), err
		}
	}
	return len(rotated), nil
}
