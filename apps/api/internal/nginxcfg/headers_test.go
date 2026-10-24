package nginxcfg

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestSecurityHeadersPreset(t *testing.T) {
	if SecurityHeadersBlock("none") != "" {
		t.Fatal("none should be empty")
	}
	basic := SecurityHeadersBlock("basic")
	if !strings.Contains(basic, "X-Content-Type-Options") {
		t.Fatal(basic)
	}
	strict := SecurityHeadersBlock("strict")
	if !strings.Contains(strict, "Strict-Transport-Security") {
		t.Fatal(strict)
	}

	h := models.ProxyHost{
		ID: uuid.New(), PrimaryDomain: "headers.example.com",
		UpstreamScheme: "http", UpstreamHost: "example.com", UpstreamPort: 80,
		PathPrefix: "/", Enabled: true, SecurityHeadersPreset: "strict",
		Aliases: []string{}, CustomHeaders: nil, Locations: nil,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	out, _, err := Render(RenderInput{Hosts: []models.ProxyHost{h}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Strict-Transport-Security") {
		t.Fatal("strict headers missing from render")
	}
	if !strings.Contains(out, "limit_req_status 429") {
		t.Fatal("429 status missing")
	}
	if !strings.Contains(out, "ssl_stapling on") {
		// only on TLS servers; without cert still have limit_req_status
		t.Log("no tls block — ocsp only on ssl server")
	}
}
