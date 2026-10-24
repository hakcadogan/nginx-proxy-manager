package nginxcfg

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nginx-proxy-waf/api/internal/models"
)

var nextUpstreamToken = map[string]bool{
	"error": true, "timeout": true, "invalid_header": true,
	"http_500": true, "http_502": true, "http_503": true, "http_504": true,
	"http_403": true, "http_404": true, "http_429": true,
	"non_idempotent": true, "off": true,
}

const DefaultNextUpstream = "error timeout http_502 http_503 http_504"

// ValidateNextUpstream checks allowlisted proxy_next_upstream tokens (REQ-LB-013).
func ValidateNextUpstream(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	seenOff := false
	for _, p := range parts {
		tok := strings.ToLower(p)
		if !nextUpstreamToken[tok] {
			return fmt.Errorf("invalid next_upstream token %q", p)
		}
		if tok == "off" {
			seenOff = true
		}
	}
	if seenOff && len(parts) > 1 {
		return fmt.Errorf("next_upstream off cannot be combined with other conditions")
	}
	return nil
}

// HasNonIdempotentRetry reports whether POST/etc may be retried to another upstream.
func HasNonIdempotentRetry(s string) bool {
	for _, p := range strings.Fields(strings.ToLower(s)) {
		if p == "non_idempotent" {
			return true
		}
	}
	return false
}

// FormatNextUpstreamDirectives emits proxy_next_upstream(+_tries/_timeout) lines.
func FormatNextUpstreamDirectives(conds string, tries int, timeout string) (string, error) {
	conds = strings.TrimSpace(conds)
	if conds == "" {
		conds = DefaultNextUpstream
	}
	if err := ValidateNextUpstream(conds); err != nil {
		return "", err
	}
	if tries < 0 || tries > 100 {
		return "", fmt.Errorf("invalid next_upstream_tries")
	}
	timeout = strings.TrimSpace(timeout)
	if timeout == "" {
		timeout = "0"
	}
	if timeout != "0" && !timeoutRe.MatchString(timeout) {
		return "", fmt.Errorf("invalid next_upstream_timeout")
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("            proxy_next_upstream %s;\n", escapeNginxString(conds)))
	if tries > 0 {
		b.WriteString(fmt.Sprintf("            proxy_next_upstream_tries %d;\n", tries))
	}
	if timeout != "0" {
		b.WriteString(fmt.Sprintf("            proxy_next_upstream_timeout %s;\n", escapeNginxString(timeout)))
	}
	return b.String(), nil
}

// NextUpstreamFromPool builds directives for a pool-bound (or default) host.
func NextUpstreamFromPool(u *models.Upstream) (string, error) {
	if u == nil {
		return FormatNextUpstreamDirectives(DefaultNextUpstream, 0, "0")
	}
	conds := u.NextUpstream
	if conds == "" {
		conds = DefaultNextUpstream
	}
	return FormatNextUpstreamDirectives(conds, u.NextUpstreamTries, u.NextUpstreamTimeout)
}

// ParseTries converts UI/API string safely.
func ParseTries(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid tries")
	}
	return n, nil
}
