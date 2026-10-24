package wafmask

import (
	"regexp"
	"strings"
)

var (
	passwordKV = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*[=:]\s*([^\s&;"']+)`)
	bearer     = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._\-+=/]+`)
	basicAuth  = regexp.MustCompile(`(?i)(basic\s+)[a-z0-9+/=]+`)
	creditCard = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
)

// Mask redacts secrets from WAF event payloads (REQ-WAF-010).
func Mask(s string) string {
	if s == "" {
		return s
	}
	out := passwordKV.ReplaceAllString(s, "${1}=***")
	out = bearer.ReplaceAllString(out, "${1}***")
	out = basicAuth.ReplaceAllString(out, "${1}***")
	out = creditCard.ReplaceAllString(out, "***")
	// JWT-like leftovers after Authorization=***
	out = regexp.MustCompile(`\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`).ReplaceAllString(out, "***")
	// Truncate oversized payloads
	if len(out) > 512 {
		out = out[:512] + "…"
	}
	return out
}

// MaskMap applies Mask to common JSON string fields.
func MaskMap(m map[string]any) {
	for k, v := range m {
		switch t := v.(type) {
		case string:
			lk := strings.ToLower(k)
			if strings.Contains(lk, "password") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "authorization") {
				m[k] = "***"
			} else {
				m[k] = Mask(t)
			}
		case map[string]any:
			MaskMap(t)
		}
	}
}
