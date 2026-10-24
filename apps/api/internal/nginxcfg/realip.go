package nginxcfg

import (
	"fmt"
	"net"
	"strings"
)

// RenderRealIP emits set_real_ip_from / real_ip_header block (trusted proxies).
func RenderRealIP(trustedCSV, header string) (string, error) {
	trustedCSV = strings.TrimSpace(trustedCSV)
	if trustedCSV == "" {
		return "", nil
	}
	if header == "" {
		header = "X-Forwarded-For"
	}
	if !headerRe.MatchString(header) {
		return "", fmt.Errorf("invalid real_ip_header")
	}
	var b strings.Builder
	for _, part := range strings.Split(trustedCSV, ",") {
		cidr := strings.TrimSpace(part)
		if cidr == "" {
			continue
		}
		if ip := net.ParseIP(cidr); ip != nil {
			b.WriteString(fmt.Sprintf("    set_real_ip_from %s;\n", cidr))
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return "", fmt.Errorf("invalid trusted proxy %q", cidr)
		}
		b.WriteString(fmt.Sprintf("    set_real_ip_from %s;\n", cidr))
	}
	if b.Len() == 0 {
		return "", nil
	}
	b.WriteString(fmt.Sprintf("    real_ip_header %s;\n", escapeNginxString(header)))
	b.WriteString("    real_ip_recursive on;\n")
	return b.String(), nil
}

// ValidateSize nginx size like 10m, 1g, 512k.
func ValidateSize(s string) error {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return fmt.Errorf("size required")
	}
	n := len(s)
	unit := s[n-1]
	num := s
	if unit == 'k' || unit == 'm' || unit == 'g' {
		num = s[:n-1]
	} else if unit < '0' || unit > '9' {
		return fmt.Errorf("invalid size unit")
	}
	if num == "" {
		return fmt.Errorf("invalid size")
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return fmt.Errorf("invalid size")
		}
	}
	return nil
}
