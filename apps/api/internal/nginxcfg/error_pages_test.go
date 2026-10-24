package nginxcfg

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestErrorPagesSnippet(t *testing.T) {
	s := ErrorPagesSnippet("        ")
	for _, want := range []string{
		"error_page 403 /nsp-error/403.html;",
		"error_page 500 /nsp-error/500.html;",
		"error_page 502 /nsp-error/502.html;",
		"location ^~ /nsp-error/",
		"alias /data/nginx/error_pages/;",
		"internal;",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

func TestRenderIncludesErrorPages(t *testing.T) {
	id := uuid.New()
	b, err := RenderAll(RenderInput{
		Hosts: []models.ProxyHost{{
			ID: id, PrimaryDomain: "err.example.com",
			UpstreamScheme: "http", UpstreamHost: "example.com", UpstreamPort: 8080,
			PathPrefix: "/", Enabled: true, ListenHTTP: true, ListenHTTPS: false,
			AccessLogEnabled: true, ErrorLogEnabled: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Main, "error_page 403 /nsp-error/403.html;") {
		t.Fatalf("main missing error_page:\n%s", b.Main)
	}
	hostConf := b.ProxyHostFiles[id.String()+".conf"]
	if hostConf == "" {
		t.Fatal("missing host conf")
	}
	for _, want := range []string{
		"error_page 403 /nsp-error/403.html;",
		"error_page 500 /nsp-error/500.html;",
		"proxy_intercept_errors on;",
		"alias /data/nginx/error_pages/;",
		"internal;",
	} {
		if !strings.Contains(hostConf, want) {
			t.Fatalf("host conf missing %q:\n%s", want, hostConf)
		}
	}
}
