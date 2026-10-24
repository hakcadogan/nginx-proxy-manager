package nginxcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestCustomIncludesEmittedWhenPresent(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"root_top.conf":     "# root top\n",
		"root.conf":         "# root end\n",
		"http_top.conf":     "# http top\n",
		"http.conf":         "# http end\n",
		"events.conf":       "# events\n",
		"stream.conf":       "# stream\n",
		"server_proxy.conf": "# per proxy server\n",
		"server_dead.conf":  "# dead\n",
		"evil.conf":         "# must never be included\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	in := RenderInput{
		CustomConfDir: dir,
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "cust.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.example.com", UpstreamPort: 80, PathPrefix: "/",
			Enabled: true, AccessLogEnabled: true, ErrorLogEnabled: true,
		}},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"include " + filepath.Join(dir, "root_top.conf") + ";",
		"include " + filepath.Join(dir, "root.conf") + ";",
		"include " + filepath.Join(dir, "http_top.conf") + ";",
		"include " + filepath.Join(dir, "http.conf") + ";",
		"include " + filepath.Join(dir, "events.conf") + ";",
		"include " + filepath.Join(dir, "server_proxy.conf") + ";",
		"include " + filepath.Join(dir, "server_dead.conf") + ";",
		"stream {",
		"include " + filepath.Join(dir, "stream.conf") + ";",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "evil.conf") {
		t.Fatal("non-allowlisted custom file must not be included")
	}
	if !strings.Contains(out, "server_name cust.example.com;") {
		t.Fatal("expected host server block")
	}
}

func TestCustomIncludesSkippedWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	in := RenderInput{
		CustomConfDir: dir,
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "plain.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.example.com", UpstreamPort: 80, PathPrefix: "/",
			Enabled: true,
		}},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "/custom/") || strings.Contains(out, dir) {
		t.Fatalf("no custom includes expected:\n%s", out)
	}
}

func TestCustomIncludeRejectsPathTraversalName(t *testing.T) {
	dir := t.TempDir()
	// Even if somehow called, basename check must reject.
	if line := customIncludeLine(dir, "../etc/passwd", ""); line != "" {
		t.Fatal("traversal name must be rejected")
	}
}
