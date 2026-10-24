package nginxcfg

import (
	"fmt"
	"regexp"
	"strings"
)

// CustomRulesBundle holds global + per-host custom ModSecurity snippets (REQ-WAF-018).
type CustomRulesBundle struct {
	Global string            `json:"global"`
	Hosts  map[string]string `json:"hosts"` // host_id -> rules text
}

const maxCustomRulesBytes = 64 * 1024

var (
	customAllowedStart = regexp.MustCompile(`^(SecRule|SecAction|SecMarker|SecRuleRemoveById|SecRuleRemoveByTag)\b`)
	// Word-boundary on lua so benign words (e.g. evaluate) are not rejected.
	customForbidden = regexp.MustCompile(`(?i)(\bInclude\b|\bIncludeOptional\b|\bSecRemoteRules\b|\bSecUploadDir\b|\bSecTmpDir\b|\bSecDataDir\b|exec:|\blua\b|\$\{)`)
)

// DefaultGlobalCustomRules is a safe starter snippet (explicit deny; not CRS anomaly scoring).
const DefaultGlobalCustomRules = `SecRule REQUEST_URI|ARGS|REQUEST_HEADERS "@rx (?i)(?:^|[/?])\.env(?:$|[/?&#])" \
    "id:1100500,phase:1,deny,status:403,log,msg:'NSP block .env access'"`

// ValidateCustomRulesText allows only SecRule/SecAction/SecMarker/Remove* lines (REQ-CFG-008).
// Multi-line rules with trailing `\` continuations are supported (including mid-quote splits).
func ValidateCustomRulesText(body string) error {
	if len(body) > maxCustomRulesBytes {
		return fmt.Errorf("custom rules max %d bytes", maxCustomRulesBytes)
	}
	if customForbidden.MatchString(body) || strings.ContainsRune(body, '`') || strings.ContainsRune(body, 0) {
		return fmt.Errorf("forbidden directive or token in custom rules")
	}
	cont := false
	for i, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if cont {
				return fmt.Errorf("line %d: comment not allowed inside backslash continuation", i+1)
			}
			continue
		}
		if cont {
			// Mid-rule continuation (may start with quote, action key, etc.).
			cont = strings.HasSuffix(line, `\`)
			continue
		}
		// Quote-only continuation without prior `\` (common indent style after SecRule).
		if strings.HasPrefix(line, `"`) || strings.HasPrefix(line, "'") {
			cont = strings.HasSuffix(line, `\`)
			continue
		}
		if !customAllowedStart.MatchString(line) {
			return fmt.Errorf("line %d: only SecRule/SecAction/SecMarker/SecRuleRemoveById|Tag allowed", i+1)
		}
		cont = strings.HasSuffix(line, `\`)
	}
	if cont {
		return fmt.Errorf("unterminated backslash continuation at end of custom rules")
	}
	return nil
}

// RenderCustomRules appends global + host-scoped custom rules into the overlay.
func RenderCustomRules(bundle CustomRulesBundle, hostDomains map[string]string) (string, error) {
	var b strings.Builder
	global := strings.TrimSpace(bundle.Global)
	if global != "" {
		if err := ValidateCustomRulesText(global); err != nil {
			return "", fmt.Errorf("global: %w", err)
		}
		b.WriteString("# REQ-WAF-018 — custom rules (global)\n")
		b.WriteString(global)
		if !strings.HasSuffix(global, "\n") {
			b.WriteByte('\n')
		}
	}
	markerN := 0
	for hostID, text := range bundle.Hosts {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if err := ValidateCustomRulesText(text); err != nil {
			return "", fmt.Errorf("host %s: %w", hostID, err)
		}
		domain := ""
		if hostDomains != nil {
			domain = hostDomains[hostID]
		}
		if domain == "" {
			return "", fmt.Errorf("host %s: unknown host for custom rules", hostID)
		}
		markerN++
		marker := fmt.Sprintf("END_NSP_CUSTOM_%d", markerN)
		b.WriteString(fmt.Sprintf("# REQ-WAF-018 — custom rules host %s (%s)\n", escapeModSec(domain), hostID))
		b.WriteString(fmt.Sprintf(
			`SecRule REQUEST_HEADERS:Host "!@rx ^%s(?::\d+)?$" \
    "id:%d,phase:1,pass,nolog,t:none,skipAfter:%s"`+"\n",
			regexp.QuoteMeta(domain), 1100000+markerN, marker))
		b.WriteString(text)
		if !strings.HasSuffix(text, "\n") {
			b.WriteByte('\n')
		}
		b.WriteString("SecMarker " + marker + "\n")
	}
	return b.String(), nil
}
