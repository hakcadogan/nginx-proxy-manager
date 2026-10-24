package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nginx-proxy-waf/api/internal/auth"
	"github.com/nginx-proxy-waf/api/internal/certs"
	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/crowdsec"
	"github.com/nginx-proxy-waf/api/internal/handlers"
	"github.com/nginx-proxy-waf/api/internal/healthprobe"
	"github.com/nginx-proxy-waf/api/internal/idssync"
	"github.com/nginx-proxy-waf/api/internal/logrotate"
	"github.com/nginx-proxy-waf/api/internal/server"
	"github.com/nginx-proxy-waf/api/internal/wafingest"
	"github.com/redis/go-redis/v9"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Error("redis", "err", err)
		os.Exit(1)
	}

	store := &db.Store{Pool: pool}
	sessions := &auth.SessionStore{RDB: rdb, TTL: cfg.SessionTTL}
	_ = os.MkdirAll(cfg.CertsDir, 0o750)
	_ = os.MkdirAll(cfg.ACMEWebRoot, 0o755)
	_ = os.MkdirAll(cfg.ACMEAccountDir, 0o700)

	handler := server.New(cfg, store, sessions, log)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	go func() {
		log.Info("api listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	// Active health probe (REQ-LB-008) — marks members down + throttled apply.
	cfgH := &handlers.ConfigHandler{Store: store, Cfg: cfg}

	// Renewal worker (REQ-SSL-008/009) — auto-renew ACME certs near expiry.
	certH := &handlers.CertHandler{
		Store: store, Cfg: cfg, FS: &certs.Store{Root: cfg.CertsDir},
		ApplyHook: cfgH.ApplyNow,
	}
	go renewLoop(cfg, store, certH, log)
	probe := healthprobe.New(store, log, cfgH.ApplyNow)
	go probe.Run(runCtx)

	// WAF audit ingest (REQ-WAF-009/012)
	go (&wafingest.Worker{Store: store, LogPath: cfg.ModsecAuditLog, Log: log}).Run(runCtx)

	// CrowdSec decision sync → nginx deny (REQ-IDS-003/004)
	csClient := &crowdsec.Client{
		BaseURL: cfg.CrowdSecLAPIURL, BouncerKey: cfg.CrowdSecBouncerKey,
		AgentURL: cfg.CrowdSecAgentURL, AgentToken: cfg.CrowdSecAgentToken,
	}
	go (&idssync.Worker{
		Store: store, CS: csClient, Log: log, Apply: cfgH.ApplyNow, FailOpen: cfg.IDSFailOpen,
	}).Run(runCtx)

	// Retention job (REQ-DATA-006) + file log rotation (REQ-OBS-006)
	go retentionLoop(store, log)
	logsH := &handlers.LogsHandler{Store: store, Cfg: cfg, Reopen: cfgH.ReopenLogs}
	go (&logrotate.Worker{Store: store, Runner: logsH, Log: log}).Run(runCtx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	runCancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func retentionLoop(store *db.Store, log *slog.Logger) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		stats, err := store.RunRetention(ctx)
		cancel()
		if err != nil {
			log.Error("retention", "err", err)
			continue
		}
		log.Info("retention completed", "deleted", stats)
	}
}

func renewLoop(cfg config.Config, store *db.Store, certH *handlers.CertHandler, log *slog.Logger) {
	t := time.NewTicker(cfg.RenewInterval)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		items, err := store.ListAutoRenewCertificates(ctx)
		if err != nil {
			cancel()
			log.Error("renew scan", "err", err)
			continue
		}
		for _, c := range items {
			days := 0
			if c.DaysRemaining != nil {
				days = *c.DaysRemaining
			}
			log.Info("certificate expiring soon",
				"id", c.ID, "name", c.Name, "days_remaining", days,
				"auto_renew", c.AutoRenew, "kind", c.Kind)
			if c.Kind != "acme" {
				continue
			}
			if _, _, err := certH.RenewCertificate(ctx, c.ID, "system-renew"); err != nil {
				log.Error("auto renew failed", "id", c.ID, "name", c.Name, "err", err.Error())
				continue
			}
			log.Info("auto renew ok", "id", c.ID, "name", c.Name)
			if certH.ApplyHook != nil {
				if err := certH.ApplyHook(ctx); err != nil {
					log.Error("auto renew apply", "id", c.ID, "err", err.Error())
				}
			}
		}
		cancel()
	}
}
