package idssync

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/nginx-proxy-waf/api/internal/crowdsec"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/models"
)

type ApplyFunc func(ctx context.Context) error

// Worker pulls CrowdSec decisions into ip_policies and optionally reapplies nginx (REQ-IDS-004).
type Worker struct {
	Store    *db.Store
	CS       *crowdsec.Client
	Log      *slog.Logger
	Apply    ApplyFunc
	FailOpen bool
	Interval time.Duration
}

func (w *Worker) Run(ctx context.Context) {
	if w.Interval <= 0 {
		w.Interval = 20 * time.Second
	}
	t := time.NewTicker(w.Interval)
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
	_, _ = w.Store.PurgeExpiredIPPolicies(ctx)
	if w.CS == nil || !w.CS.Enabled() {
		return
	}
	decisions, err := w.CS.Decisions(ctx)
	if err != nil {
		w.Log.Warn("crowdsec sync", "err", err.Error()) // never log key
		if w.FailOpen {
			// Lab: drop crowdsec-sourced bans when LAPI down (RISK-07 fail-open)
			_ = w.Store.DeleteCrowdSecPoliciesNotIn(ctx, nil)
		}
		// fail-closed: keep existing crowdsec rows
		return
	}
	before, _ := w.Store.ListIPPolicies(ctx, "")
	beforeFP := policyFingerprint(before)

	keep := make([]string, 0, len(decisions))
	for _, d := range decisions {
		if !strings.EqualFold(d.Type, "ban") {
			continue
		}
		if d.Value == "" {
			continue
		}
		ext := strconv.FormatInt(d.ID, 10)
		if ext == "0" {
			ext = d.Origin + ":" + d.Value + ":" + d.Scenario
		}
		keep = append(keep, ext)
		var exp *time.Time
		if d.Duration != "" && d.Duration != "0s" {
			if dur, err := time.ParseDuration(d.Duration); err == nil {
				t := time.Now().UTC().Add(dur)
				exp = &t
			}
		}
		reason := d.Scenario
		if reason == "" {
			reason = "crowdsec"
		}
		_ = w.Store.UpsertCrowdSecDecision(ctx, ext, d.Value, reason, exp)
		_, _ = w.Store.InsertSecurityEvent(ctx, models.SecurityEvent{
			Source: "crowdsec", RuleID: d.Scenario, Message: reason,
			ClientIP: d.Value, PayloadSummary: fmt.Sprintf("ban %s via %s", d.Value, d.Origin),
			UniqueID: "cs-" + ext,
		})
	}
	if err := w.Store.DeleteCrowdSecPoliciesNotIn(ctx, keep); err != nil {
		w.Log.Error("crowdsec purge", "err", err)
		return
	}
	after, _ := w.Store.ListIPPolicies(ctx, "")
	if policyFingerprint(after) == beforeFP || w.Apply == nil {
		return
	}
	applyCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := w.Apply(applyCtx); err != nil {
		w.Log.Error("crowdsec apply", "err", err)
	}
}

func policyFingerprint(items []models.IPPolicy) string {
	parts := make([]string, 0, len(items))
	for _, p := range items {
		parts = append(parts, p.Kind+"|"+p.IPCIDR+"|"+p.Source+"|"+p.ExternalID)
	}
	return strings.Join(parts, ";")
}
