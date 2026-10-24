package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CrowdSec agent: apply allowlisted scenario/profile overrides + reload (REQ-IDS-017).
// No Docker socket. Only writes under /etc/crowdsec and signals crowdsec process.

type applyReq struct {
	Files map[string]string `json:"files"` // basename -> content
}

var allowedFiles = map[string]string{
	"http-probing.yaml":           "/etc/crowdsec/scenarios/http-probing.yaml",
	"http-crawl-non_statics.yaml": "/etc/crowdsec/scenarios/http-crawl-non_statics.yaml",
	"http-generic-bf.yaml":        "/etc/crowdsec/scenarios/http-generic-bf.yaml",
	"profiles.yaml":               "/etc/crowdsec/profiles.yaml",
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	token := os.Getenv("CROWDSEC_AGENT_TOKEN")
	if token == "" {
		log.Error("CROWDSEC_AGENT_TOKEN required")
		os.Exit(1)
	}
	addr := getenv("HTTP_ADDR", ":8091")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /v1/apply", auth(token, func(w http.ResponseWriter, r *http.Request) {
		var req applyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Files) == 0 {
			writeJSON(w, 400, map[string]any{"ok": false, "message": "files required"})
			return
		}
		if err := os.MkdirAll("/nsp-overrides", 0o755); err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		for name, body := range req.Files {
			base := filepath.Base(name)
			dest, ok := allowedFiles[base]
			if !ok {
				writeJSON(w, 400, map[string]any{"ok": false, "message": "file not allowed: " + name})
				return
			}
			if strings.Contains(body, "\x00") || len(body) > 200_000 {
				writeJSON(w, 400, map[string]any{"ok": false, "message": "invalid body"})
				return
			}
			tmp := dest + ".tmp"
			if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
				writeJSON(w, 500, map[string]any{"ok": false, "message": err.Error()})
				return
			}
			if err := os.Rename(tmp, dest); err != nil {
				writeJSON(w, 500, map[string]any{"ok": false, "message": err.Error()})
				return
			}
			// Persist for container restart (boot entrypoint re-applies from here).
			persist := filepath.Join("/nsp-overrides", base)
			if err := os.WriteFile(persist, []byte(body), 0o644); err != nil {
				writeJSON(w, 500, map[string]any{"ok": false, "message": "persist: " + err.Error()})
				return
			}
		}
		if out, err := reloadCrowdSec(); err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "message": "reload failed: " + out})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "message": "applied", "files": len(req.Files)})
	}))

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Info("crowdsec-agent listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func reloadCrowdSec() (string, error) {
	// After docker_start exec, PID 1 is crowdsec. Prefer kill -HUP 1.
	// Avoid pkill: it can race during startup and terminate before handlers are ready.
	cmd := exec.Command("kill", "-HUP", "1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), nil
	}
	// Fallback: named process
	cmd2 := exec.Command("pkill", "-HUP", "-x", "crowdsec")
	out2, err2 := cmd2.CombinedOutput()
	return string(out) + string(out2), err2
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
