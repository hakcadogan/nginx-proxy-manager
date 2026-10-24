package nginxcfg

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestDefaultRetryAfterSeconds(t *testing.T) {
	if DefaultRetryAfterSeconds(10) != 1 {
		t.Fatal("10 r/s → 1s")
	}
	if DefaultRetryAfterSeconds(0.5) != 2 {
		t.Fatal("0.5 r/s → 2s")
	}
	if NormalizeRetryAfterSeconds(0, 5) != 1 {
		t.Fatal("0 → derive")
	}
	if NormalizeRetryAfterSeconds(30, 10) != 30 {
		t.Fatal("explicit 30")
	}
}

func TestErrorPagesRetryAfter(t *testing.T) {
	s := ErrorPagesSnippetOpts("        ", 15)
	for _, want := range []string{
		"error_page 429 =429 @nsp_rl_429;",
		"location @nsp_rl_429",
		"add_header Retry-After 15 always;",
		"try_files /429.html =429;",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "error_page 429 /nsp-error/429.html;") {
		t.Fatal("must not use plain 429 page when Retry-After set")
	}
}

func TestRenderRateLimitRetryAfterHeader(t *testing.T) {
	profileID := uuid.New()
	in := RenderInput{
		TrustedProxies: "10.0.0.0/8",
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "app.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.internal", UpstreamPort: 8080, PathPrefix: "/", Enabled: true,
			RateLimitProfileID: &profileID, ListenHTTP: true,
		}},
		Profiles: map[string]models.RateLimitProfile{
			profileID.String(): {
				Name: "api", RequestsPerSecond: 10, Burst: 5, ConnectionsPerIP: 10,
				RetryAfterSeconds: 7,
			},
		},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "add_header Retry-After 7 always;") {
		t.Fatalf("missing Retry-After:\n%s", out)
	}
	if !strings.Contains(out, "@nsp_rl_429") {
		t.Fatal("missing named 429 location")
	}
}
