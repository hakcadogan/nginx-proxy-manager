package healthprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/models"
)

// ApplyFunc re-renders and reloads nginx when member health changes (REQ-LB-008).
type ApplyFunc func(ctx context.Context) error

// Worker runs active health probes and marks members down (OSS emulation of Plus health_check).
type Worker struct {
	Store      *db.Store
	Log        *slog.Logger
	Apply      ApplyFunc
	HTTPClient *http.Client

	mu           sync.Mutex
	lastApply    time.Time
	minApplyGap  time.Duration
	tickInterval time.Duration
}

func New(store *db.Store, log *slog.Logger, apply ApplyFunc) *Worker {
	return &Worker{
		Store: store,
		Log:   log,
		Apply: apply,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // lab backends may use self-signed
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		minApplyGap:  15 * time.Second,
		tickInterval: 5 * time.Second,
	}
}

func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.tickInterval)
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
	ups, err := w.Store.ListHealthCheckUpstreams(ctx)
	if err != nil {
		w.Log.Error("healthprobe list", "err", err)
		return
	}
	changed := false
	for _, u := range ups {
		interval := time.Duration(u.HealthCheckIntervalSec) * time.Second
		if interval < 5*time.Second {
			interval = 10 * time.Second
		}
		for _, m := range u.Members {
			if m.IsDrain {
				continue // drain stays down; skip probe apply noise
			}
			// Admin-disabled members stay down; still probe so last_check_* stays fresh.
			if m.LastCheckAt != nil && time.Since(*m.LastCheckAt) < interval {
				continue
			}
			ok := w.check(ctx, u, m)
			didChange, err := w.Store.SetMemberHealth(ctx, m.ID, ok)
			if err != nil {
				w.Log.Error("healthprobe update", "member", m.ID, "err", err)
				continue
			}
			if didChange {
				changed = true
				w.Log.Info("healthprobe state change",
					"upstream", u.Name, "host", m.Host, "port", m.Port, "ok", ok)
			}
		}
	}
	if !changed || w.Apply == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Since(w.lastApply) < w.minApplyGap {
		return
	}
	applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := w.Apply(applyCtx); err != nil {
		w.Log.Error("healthprobe apply", "err", err)
		return
	}
	w.lastApply = time.Now()
}

func (w *Worker) check(ctx context.Context, u models.Upstream, m models.UpstreamMember) bool {
	path := u.HealthCheckPath
	if path == "" {
		path = "/"
	}
	url := fmt.Sprintf("%s://%s:%d%s", u.Scheme, m.Host, m.Port, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	if u.SNI != "" {
		req.Host = u.SNI
	}
	res, err := w.HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 500
}
