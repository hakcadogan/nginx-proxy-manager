package nginxcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const CRSRulesCatalogFile = "crs-rules-catalog.json"

// RuleIDValid reports whether id is a numeric ModSecurity rule id.
func RuleIDValid(id string) bool {
	return ruleIDRe.MatchString(strings.TrimSpace(id))
}

// CRSRuleCatalogEntry is one CRS/NSP rule surfaced in the UI (REQ-WAF-007).
type CRSRuleCatalogEntry struct {
	ID       string `json:"id"`
	Msg      string `json:"msg"`
	File     string `json:"file"`
	Paranoia int    `json:"paranoia"`
	Category string `json:"category"`
	Phase    int    `json:"phase"`
}

type crsCatalogFile struct {
	Items []CRSRuleCatalogEntry `json:"items"`
	Count int                   `json:"count"`
}

// LoadCRSRulesCatalog reads the JSON catalog from modsecDir (or fallbacks).
func LoadCRSRulesCatalog(modsecDir string) ([]CRSRuleCatalogEntry, error) {
	candidates := []string{
		filepath.Join(modsecDir, CRSRulesCatalogFile),
		"/etc/nginx/modsec/" + CRSRulesCatalogFile,
	}
	var lastErr error
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		var doc crsCatalogFile
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("crs catalog: %w", err)
		}
		return doc.Items, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("crs catalog not found: %w", lastErr)
	}
	return nil, fmt.Errorf("crs catalog not found")
}

// NormalizeDisabledRuleIDs validates and dedupes numeric rule IDs.
func NormalizeDisabledRuleIDs(ids []string) ([]string, error) {
	if len(ids) > 2000 {
		return nil, fmt.Errorf("disabled rules max 2000")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if !ruleIDRe.MatchString(id) {
			return nil, fmt.Errorf("invalid rule id %q", id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, _ := strconv.Atoi(out[i])
		aj, _ := strconv.Atoi(out[j])
		return ai < aj
	})
	return out, nil
}

// FilterCRSRules applies search / category / paranoia / enabled filters.
func FilterCRSRules(
	items []CRSRuleCatalogEntry,
	disabled map[string]bool,
	q, category, enabledFilter string,
	paranoia int,
) []CRSRuleCatalogEntry {
	q = strings.ToLower(strings.TrimSpace(q))
	category = strings.ToLower(strings.TrimSpace(category))
	enabledFilter = strings.ToLower(strings.TrimSpace(enabledFilter))
	out := make([]CRSRuleCatalogEntry, 0, len(items))
	for _, it := range items {
		if paranoia > 0 && it.Paranoia > 0 && it.Paranoia > paranoia {
			continue
		}
		if category != "" && category != "all" && strings.ToLower(it.Category) != category {
			continue
		}
		isEnabled := !disabled[it.ID]
		switch enabledFilter {
		case "active", "enabled", "on":
			if !isEnabled {
				continue
			}
		case "passive", "disabled", "off":
			if isEnabled {
				continue
			}
		}
		if q != "" {
			hay := strings.ToLower(it.ID + " " + it.Msg + " " + it.File + " " + it.Category)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, it)
	}
	return out
}

// DisabledRuleSet converts ID list to a set.
func DisabledRuleSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}
