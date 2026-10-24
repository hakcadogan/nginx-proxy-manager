package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Config agent: validate + atomic publish + reload + rollback (REQ-CFG-002..007, REQ-CFG-010).
// No Docker socket. Only nginx -t and nginx -s reload against local filesystem.

type applyReq struct {
	StagingConf string `json:"staging_conf"`
}

var chaosFailNext atomic.Bool

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	token := os.Getenv("CONFIG_AGENT_TOKEN")
	if token == "" {
		log.Error("CONFIG_AGENT_TOKEN required")
		os.Exit(1)
	}
	liveConf := getenv("NGINX_LIVE_CONF", "/etc/nginx/nginx.conf")
	lastGoodDir := getenv("NGINX_LAST_GOOD_DIR", "/var/lib/nsp/last-good")
	chaosFlag := getenv("CHAOS_FLAG_FILE", "/var/lib/nsp/chaos-fail-reload")
	addr := getenv("HTTP_ADDR", ":8090")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /v1/validate", auth(token, func(w http.ResponseWriter, r *http.Request) {
		var req applyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.StagingConf == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "message": "staging_conf required"})
			return
		}
		out, err := runNginxT(req.StagingConf)
		if err != nil {
			writeJSON(w, 422, map[string]any{"ok": false, "message": out})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "message": "nginx -t ok"})
	}))
	mux.HandleFunc("POST /v1/apply", auth(token, func(w http.ResponseWriter, r *http.Request) {
		var req applyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.StagingConf == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "message": "staging_conf required"})
			return
		}
		out, err := runNginxT(req.StagingConf)
		if err != nil {
			writeJSON(w, 422, map[string]any{"ok": false, "message": out})
			return
		}
		if err := os.MkdirAll(lastGoodDir, 0o755); err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		before, _ := os.ReadFile(liveConf)
		if _, err := os.Stat(liveConf); err == nil {
			_ = copyFile(liveConf, filepath.Join(lastGoodDir, "nginx.conf"))
		}
		if err := copyFile(req.StagingConf, liveConf); err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "message": "publish failed: " + err.Error()})
			return
		}
		reloadOut, err := runNginxReload(chaosFlag)
		if err != nil {
			lg := filepath.Join(lastGoodDir, "nginx.conf")
			if _, serr := os.Stat(lg); serr == nil {
				_ = copyFile(lg, liveConf)
				_, _ = runNginxReload("")
			}
			after, _ := os.ReadFile(liveConf)
			rolled := len(before) > 0 && string(before) == string(after)
			writeJSON(w, 409, map[string]any{
				"ok": false, "message": "reload failed, rolled back: " + reloadOut, "rolled_back": rolled,
			})
			return
		}
		_ = copyFile(liveConf, filepath.Join(lastGoodDir, "nginx.conf"))
		writeJSON(w, 200, map[string]any{"ok": true, "message": "applied"})
	}))
	// Reopen log files after rotation (REQ-OBS-006) — does not reload config.
	mux.HandleFunc("POST /v1/reopen", auth(token, func(w http.ResponseWriter, r *http.Request) {
		cmd := exec.Command("nginx", "-s", "reopen")
		out, err := cmd.CombinedOutput()
		if err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "message": string(out)})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "message": "reopened"})
	}))
	// Test-only arming for reload chaos (REQ-CFG-005). Requires agent token.
	mux.HandleFunc("POST /v1/chaos/fail-next-reload", auth(token, func(w http.ResponseWriter, r *http.Request) {
		chaosFailNext.Store(true)
		_ = os.WriteFile(chaosFlag, []byte("1"), 0o644)
		writeJSON(w, 200, map[string]any{"ok": true, "message": "next reload will fail once"})
	}))

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Info("config-agent listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func auth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Token") != token {
			writeJSON(w, 401, map[string]any{"ok": false, "message": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func runNginxT(conf string) (string, error) {
	cmd := exec.Command("nginx", "-t", "-c", conf)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runNginxReload(chaosFlag string) (string, error) {
	if chaosFailNext.Swap(false) {
		if chaosFlag != "" {
			_ = os.Remove(chaosFlag)
		}
		return "chaos: forced reload failure", errors.New("chaos fail")
	}
	if chaosFlag != "" {
		if _, err := os.Stat(chaosFlag); err == nil {
			_ = os.Remove(chaosFlag)
			return "chaos: forced reload failure (flag file)", errors.New("chaos fail")
		}
	}
	cmd := exec.Command("nginx", "-s", "reload")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
