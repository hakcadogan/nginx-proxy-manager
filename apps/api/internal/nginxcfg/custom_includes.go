package nginxcfg

import (
	"os"
	"path/filepath"
	"strings"
)

// NPM-compatible named custom includes under /data/nginx/custom (REQ-PROXY-021).
// Operator drop-in files only — no UI editor. Unknown filenames are never included.
// Each include is emitted only when the file exists (nginx has no optional include).
var allowedCustomFiles = map[string]struct{}{
	"root_top.conf":           {},
	"root.conf":               {},
	"http_top.conf":           {},
	"http.conf":               {},
	"events.conf":             {},
	"stream.conf":             {},
	"server_proxy.conf":       {},
	"server_redirect.conf":    {}, // reserved (redirect hosts not yet modeled)
	"server_stream.conf":      {}, // reserved (stream servers not yet modeled)
	"server_stream_tcp.conf":  {},
	"server_stream_udp.conf":  {},
	"server_dead.conf":        {},
}

// AllowedCustomIncludeNames returns the NPM-style allowlist (docs order).
func AllowedCustomIncludeNames() []string {
	order := []string{
		"root_top.conf", "root.conf", "http_top.conf", "http.conf", "events.conf", "stream.conf",
		"server_proxy.conf", "server_redirect.conf", "server_stream.conf",
		"server_stream_tcp.conf", "server_stream_udp.conf", "server_dead.conf",
	}
	out := make([]string, 0, len(order))
	for _, n := range order {
		if _, ok := allowedCustomFiles[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

func resolveCustomDir(override string) string {
	if strings.TrimSpace(override) != "" {
		return filepath.Clean(override)
	}
	return CustomConfDir
}

// customIncludeLine returns an indented include directive if the allowlisted file exists.
func customIncludeLine(dir, name, indent string) string {
	if _, ok := allowedCustomFiles[name]; !ok {
		return ""
	}
	// basename only — reject path traversal
	if name != filepath.Base(name) || strings.Contains(name, "..") {
		return ""
	}
	path := filepath.Join(dir, name)
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return ""
	}
	return indent + "include " + escapeNginxString(path) + ";\n"
}

// CustomIncludes holds pre-rendered optional include snippets for the main template.
type CustomIncludes struct {
	RootTop     string
	Root        string
	HTTPTop     string
	HTTP        string
	Events      string
	StreamBlock string // full "stream { include … }" or empty
	ServerProxy string // injected into every proxy host server block
	ServerDead  string // injected into fallback/default_server
}

// LoadCustomIncludes reads allowlisted drop-in files from dir (REQ-PROXY-021).
func LoadCustomIncludes(dir string) CustomIncludes {
	dir = resolveCustomDir(dir)
	var c CustomIncludes
	c.RootTop = customIncludeLine(dir, "root_top.conf", "")
	c.Root = customIncludeLine(dir, "root.conf", "")
	c.HTTPTop = customIncludeLine(dir, "http_top.conf", "    ")
	c.HTTP = customIncludeLine(dir, "http.conf", "    ")
	c.Events = customIncludeLine(dir, "events.conf", "    ")
	c.ServerProxy = customIncludeLine(dir, "server_proxy.conf", "        ")
	c.ServerDead = customIncludeLine(dir, "server_dead.conf", "        ")
	if line := customIncludeLine(dir, "stream.conf", "    "); line != "" {
		c.StreamBlock = "stream {\n" + line + "}\n"
	}
	return c
}
