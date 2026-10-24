package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ConfigReloadTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nsp_config_reload_total",
		Help: "Config apply/reload attempts",
	}, []string{"result"})

	RateLimitHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nsp_rate_limit_hits_total",
		Help: "Control-plane API rate limit hits",
	})

	LoginFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nsp_login_failures_total",
		Help: "Failed login attempts",
	})

	LoginLockouts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nsp_login_lockouts_total",
		Help: "Account lockouts after failed logins",
	})

	UpstreamMembers = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nsp_upstream_members",
		Help: "Upstream pool member counts by state",
	}, []string{"pool", "state"})

	CertExpiryDays = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nsp_certificate_days_remaining",
		Help: "Days remaining until certificate expiry",
	}, []string{"name", "id"})

	AlertsFired = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nsp_alerts_fired_total",
		Help: "Alert rule firings",
	}, []string{"alert"})
)

func Handler() http.Handler {
	return promhttp.Handler()
}
