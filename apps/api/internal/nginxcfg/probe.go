package nginxcfg

import (
	"fmt"
	"net"
	"time"

	"github.com/nginx-proxy-waf/api/internal/models"
)

// ProbeResult is a TCP connectivity check against a host upstream (REQ-PROXY-020).
type ProbeResult struct {
	OK       bool   `json:"ok"`
	Target   string `json:"target"`
	LatencyMS int64 `json:"latency_ms"`
	Error    string `json:"error,omitempty"`
}

// ProbeHostUpstream dials the configured upstream (or first pool member target via host fields).
func ProbeHostUpstream(h models.ProxyHost, timeout time.Duration) ProbeResult {
	NormalizeHostFields(&h)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	host := h.UpstreamHost
	port := h.UpstreamPort
	if host == "" || host == "pool.local" {
		return ProbeResult{OK: false, Error: "direct upstream required for probe (use pool members for LB pools)"}
	}
	if !hostRe.MatchString(host) || isBlockedUpstream(host) {
		return ProbeResult{OK: false, Error: "upstream host not allowed"}
	}
	if port < 1 || port > 65535 {
		return ProbeResult{OK: false, Error: "invalid port"}
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return ProbeResult{OK: false, Target: target, LatencyMS: lat, Error: err.Error()}
	}
	_ = conn.Close()
	return ProbeResult{OK: true, Target: target, LatencyMS: lat}
}
