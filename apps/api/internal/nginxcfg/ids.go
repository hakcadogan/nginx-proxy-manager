package nginxcfg

import (
	"fmt"
	"net"
	"strings"

	"github.com/nginx-proxy-waf/api/internal/models"
)

// RenderIPAccess builds allow/deny directives for the http{} context once (REQ-IDS-003..007).
// Order: allowlist first, then deny/ban. Allowlisted IPs are never denied.
// Indent is 4 spaces (http-level); do not duplicate per server — that balloons conf and reload cost.
// When enforcement is "passive" (REQ-IDS-019), no allow/deny is emitted — CrowdSec/DB still track decisions.
func RenderIPAccess(policies []models.IPPolicy) (string, error) {
	return RenderIPAccessMode(policies, "active")
}

// RenderIPAccessMode is RenderIPAccess with explicit enforcement mode (active|passive).
func RenderIPAccessMode(policies []models.IPPolicy, enforcement string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(enforcement), "passive") {
		return "    # IDS/IPS enforcement: passive — allow/deny not applied (REQ-IDS-019)\n", nil
	}
	allows := map[string]bool{}
	var allowLines []string
	for _, p := range policies {
		ip := strings.TrimSpace(p.IPCIDR)
		if ip == "" {
			continue
		}
		if err := ValidateIPCIDR(ip); err != nil {
			return "", fmt.Errorf("ip_policy %s: %w", p.ID, err)
		}
		safe := escapeNginxString(ip)
		if p.Kind == "allow" {
			allows[normalizeIPKey(ip)] = true
			allowLines = append(allowLines, fmt.Sprintf("    allow %s;", safe))
		}
	}
	var b strings.Builder
	if len(policies) > 0 {
		b.WriteString("    # IDS/IPS IP access (shared; REQ-IDS-003..007)\n")
	}
	for _, line := range allowLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, p := range policies {
		if p.Kind != "deny" && p.Kind != "ban" {
			continue
		}
		if allows[normalizeIPKey(p.IPCIDR)] {
			continue // allowlist wins (REQ-IDS-006)
		}
		b.WriteString(fmt.Sprintf("    deny %s; # %s/%s\n",
			escapeNginxString(strings.TrimSpace(p.IPCIDR)), p.Kind, escapeNginxString(p.Source)))
	}
	return b.String(), nil
}

func ValidateIPCIDR(s string) error {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("invalid cidr")
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid ip")
	}
	return nil
}

func normalizeIPKey(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String()
	}
	return s
}
