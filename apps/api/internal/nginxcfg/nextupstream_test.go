package nginxcfg

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestFormatNextUpstreamDefault(t *testing.T) {
	out, err := FormatNextUpstreamDirectives("", 0, "0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "proxy_next_upstream error timeout http_502 http_503 http_504;") {
		t.Fatalf("got %q", out)
	}
	if strings.Contains(out, "tries") {
		t.Fatal("tries should be omitted when 0")
	}
}

func TestFormatNextUpstreamNonIdempotent(t *testing.T) {
	out, err := FormatNextUpstreamDirectives("error timeout non_idempotent", 2, "5s")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"proxy_next_upstream error timeout non_idempotent;",
		"proxy_next_upstream_tries 2;",
		"proxy_next_upstream_timeout 5s;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	if !HasNonIdempotentRetry("error non_idempotent") {
		t.Fatal("expected non_idempotent detect")
	}
}

func TestValidateNextUpstreamReject(t *testing.T) {
	if err := ValidateNextUpstream("error exec"); err == nil {
		t.Fatal("expected reject")
	}
	if err := ValidateNextUpstream("off error"); err == nil {
		t.Fatal("off must be alone")
	}
}

func TestRenderPoolNextUpstream(t *testing.T) {
	poolID := uuid.New()
	u := models.Upstream{
		ID: poolID, Name: "p", Algorithm: "round_robin", Scheme: "http",
		ConnectTimeout: "5s", SendTimeout: "60s", ReadTimeout: "60s",
		MaxFails: 3, FailTimeout: "10s",
		NextUpstream: "error timeout", NextUpstreamTries: 3, NextUpstreamTimeout: "10s",
		Members: []models.UpstreamMember{{Host: "a.example.com", Port: 80, Weight: 1}},
	}
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "app.example.com", UpstreamScheme: "http",
			UpstreamHost: "pool.local", UpstreamPort: 80, PathPrefix: "/",
			Enabled: true, ListenHTTP: true, ListenHTTPS: false, UpstreamID: &poolID,
		}},
		Upstreams: map[string]models.Upstream{poolID.String(): u},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"proxy_next_upstream error timeout;",
		"proxy_next_upstream_tries 3;",
		"proxy_next_upstream_timeout 10s;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
