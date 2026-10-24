package nginxcfg

import (
	"fmt"
	"strings"
)

var allowedHTTPMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

// NormalizeMethods uppercases and validates HTTP method names. Empty = unrestricted.
func NormalizeMethods(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range in {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if !allowedHTTPMethods[m] {
			return nil, fmt.Errorf("invalid http method: %s", m)
		}
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out, nil
}

// RenderMethodGuard emits an if-block that returns 405 for disallowed methods (REQ-RATE-007).
func RenderMethodGuard(methods []string, indent string) string {
	norm, err := NormalizeMethods(methods)
	if err != nil || len(norm) == 0 {
		return ""
	}
	pat := strings.Join(norm, "|")
	return fmt.Sprintf("%sif ($request_method !~ ^(%s)$) {\n%s    return 405;\n%s}\n",
		indent, pat, indent, indent)
}
