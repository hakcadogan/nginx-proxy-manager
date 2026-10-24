package nginxcfg

import (
	"fmt"
	"net"
	"strings"
)

// DefaultProtectedCIDRs never receive ban/deny from the control plane (REQ-IDS-014).
const DefaultProtectedCIDRs = "127.0.0.1,::1"

// ParseCIDRList splits CSV of IPs/CIDRs.
func ParseCIDRList(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IsProtectedIP reports whether ipOrCIDR overlaps any protected network.
func IsProtectedIP(ipOrCIDR string, protectedCSV string) bool {
	if protectedCSV == "" {
		protectedCSV = DefaultProtectedCIDRs
	}
	target := strings.TrimSpace(ipOrCIDR)
	tip := net.ParseIP(target)
	var tnet *net.IPNet
	if tip == nil {
		_, n, err := net.ParseCIDR(target)
		if err != nil {
			return false
		}
		tnet = n
	}
	for _, p := range ParseCIDRList(protectedCSV) {
		if tip != nil {
			if pip := net.ParseIP(p); pip != nil && tip.Equal(pip) {
				return true
			}
			if _, n, err := net.ParseCIDR(p); err == nil && n.Contains(tip) {
				return true
			}
			continue
		}
		// target is a network — protect if equal or contained in protected
		if tnet == nil {
			continue
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			if n.String() == tnet.String() || n.Contains(tnet.IP) {
				return true
			}
		}
		if pip := net.ParseIP(p); pip != nil && tnet.Contains(pip) && ones(tnet) >= 32 {
			return true
		}
	}
	return false
}

func ones(n *net.IPNet) int {
	o, _ := n.Mask.Size()
	return o
}

// ValidateProtectedBan returns error if ban/deny would hit protected infra.
func ValidateProtectedBan(ip string, protectedCSV string) error {
	if IsProtectedIP(ip, protectedCSV) {
		return fmt.Errorf("ip %s is protected (management/loopback); allowlist instead of ban/deny", ip)
	}
	return nil
}
