package nginxcfg

import (
	"strings"
	"testing"

	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestRenderRealIP(t *testing.T) {
	out, err := RenderRealIP("10.0.0.0/8, 192.168.1.1", "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set_real_ip_from 10.0.0.0/8;",
		"set_real_ip_from 192.168.1.1;",
		"real_ip_header X-Forwarded-For;",
		"real_ip_recursive on;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestRenderRealIPReject(t *testing.T) {
	if _, err := RenderRealIP("not-a-cidr", "X-Forwarded-For"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderAdvancedHost(t *testing.T) {
	in := RenderInput{
		TrustedProxies: "10.0.0.0/8",
		RealIPHeader:   "X-Forwarded-For",
		Hosts: []models.ProxyHost{{
			PrimaryDomain:     "adv.example.com",
			UpstreamScheme:    "http",
			UpstreamHost:      "backend.example.com",
			UpstreamPort:      8080,
			PathPrefix:        "/",
			Enabled:           true,
			ListenHTTP:        true,
			ListenHTTPS:       false,
			HTTP2:             false,
			ClientMaxBodySize: "25m",
			ConnectTimeout:    "2s",
			SendTimeout:       "30s",
			ReadTimeout:       "30s",
			ProxyProtocol:     "http",
			AccessLogEnabled:  true,
		}},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set_real_ip_from 10.0.0.0/8;",
		"client_max_body_size 25m;",
		"proxy_connect_timeout 2s;",
		"listen 80;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "listen 443") {
		t.Fatal("https listen should be omitted")
	}
}

func TestRenderGRPC(t *testing.T) {
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain:  "grpc.example.com",
			UpstreamScheme: "http",
			UpstreamHost:   "backend.example.com",
			UpstreamPort:   50051,
			PathPrefix:     "/",
			Enabled:        true,
			ListenHTTP:     true,
			ListenHTTPS:    false,
			ProxyProtocol:  "grpc",
		}},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "grpc_pass grpc://up_0;") {
		t.Fatalf("expected grpc_pass, got:\n%s", out)
	}
	if strings.Contains(out, "proxy_pass") {
		t.Fatal("grpc host must not use proxy_pass")
	}
}

func TestValidateSize(t *testing.T) {
	for _, s := range []string{"10m", "1g", "512k", "100"} {
		if err := ValidateSize(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := ValidateSize("10x"); err == nil {
		t.Fatal("expected invalid")
	}
}
