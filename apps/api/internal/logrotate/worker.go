package logrotate

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/nginx-proxy-waf/api/internal/db"
)

type Runner interface {
	RunOnce(ctx context.Context) (int, error)
}

// Worker periodically rotates oversized logs (REQ-OBS-006).
type Worker struct {
	Store  *db.Store
	Runner Runner
	Log    *slog.Logger

	mu      sync.Mutex
	lastRun time.Time
}

func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	w.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	intervalMin := 60
	if v, _ := w.Store.GetSetting(ctx, "log_rotate_interval_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 {
			intervalMin = n
		}
	}
	w.mu.Lock()
	due := w.lastRun.IsZero() || time.Since(w.lastRun) >= time.Duration(intervalMin)*time.Minute
	if due {
		w.lastRun = time.Now()
	}
	w.mu.Unlock()
	if !due {
		return
	}
	n, err := w.Runner.RunOnce(ctx)
	if err != nil {
		w.Log.Error("logrotate", "err", err)
		return
	}
	if n > 0 {
		w.Log.Info("logrotate", "rotated", n)
	}
}
