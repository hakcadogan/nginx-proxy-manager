package nginxcfg

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestDefaultServersRejectUnmatchedHost(t *testing.T) {
	out, _, err := Render(RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "app.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.example.com", UpstreamPort: 80, PathPrefix: "/",
			Enabled: true, ListenHTTP: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "listen 80 default_server;") {
		t.Fatal("missing HTTP default_server")
	}
	if !strings.Contains(out, "listen 443 ssl default_server;") {
		t.Fatal("missing HTTPS default_server")
	}
	if !strings.Contains(out, "ssl_reject_handshake on;") {
		t.Fatal("missing ssl_reject_handshake for bare-IP / unknown Host")
	}
}

func TestRenderBasicHost(t *testing.T) {
	profileID := uuid.New()
	in := RenderInput{
		TrustedProxies: "10.0.0.0/8",
		Hosts: []models.ProxyHost{{
			PrimaryDomain:      "app.example.com",
			Aliases:            []string{"www.app.example.com"},
			UpstreamScheme:     "http",
			UpstreamHost:       "backend.internal",
			UpstreamPort:       8080,
			PathPrefix:         "/",
			Enabled:            true,
			WebsocketSupport:   true,
			AccessLogEnabled:   true,
			RateLimitProfileID: &profileID,
			AllowedMethods:     []string{"GET", "POST"},
			CustomHeaders: []models.HeaderRule{
				{Action: "add", Name: "X-App", Value: "nsp"},
			},
			Locations: []models.LocationRule{{
				Path: "/api/", UpstreamScheme: "http", UpstreamHost: "api.internal", UpstreamPort: 9000,
				RateLimitProfileID: profileID.String(), AllowedMethods: []string{"GET"},
			}},
		}},
		Profiles: map[string]models.RateLimitProfile{
			profileID.String(): {
				Name:              "default",
				RequestsPerSecond: 10,
				Burst:             20,
				ConnectionsPerIP:  20,
			},
		},
	}
	out, sum, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if sum == "" {
		t.Fatal("expected checksum")
	}
	for _, want := range []string{
		"server_name app.example.com www.app.example.com;",
		"proxy_pass http://up_0;",
		"limit_req zone=rl_default",
		"proxy_set_header Upgrade $http_upgrade;",
		"proxy_set_header X-App nsp;",
		"connection_upgrade",
		"if ($request_method !~ ^(GET|POST)$)",
		"location /api/",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRateLimitBurstZeroOmitsBurstParam(t *testing.T) {
	profileID := uuid.New()
	in := RenderInput{
		TrustedProxies: "10.0.0.0/8",
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "app.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.internal", UpstreamPort: 8080, PathPrefix: "/", Enabled: true,
			RateLimitProfileID: &profileID, ListenHTTP: true,
		}},
		Profiles: map[string]models.RateLimitProfile{
			profileID.String(): {Name: "strict", RequestsPerSecond: 5, Burst: 0, ConnectionsPerIP: 10},
		},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "burst=0") {
		t.Fatal("nginx rejects burst=0; must omit burst param")
	}
	if !strings.Contains(out, "limit_req zone=rl_strict;") {
		t.Fatalf("expected limit_req without burst, got:\n%s", out)
	}
	if strings.Contains(out, "limit_req zone=rl_strict burst=") {
		t.Fatal("burst=0 must not emit burst=")
	}
}

func TestRateLimitSkippedWithoutTrustedProxies(t *testing.T) {
	profileID := uuid.New()
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "app.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.internal", UpstreamPort: 8080, PathPrefix: "/", Enabled: true,
			RateLimitProfileID: &profileID,
		}},
		Profiles: map[string]models.RateLimitProfile{
			profileID.String(): {Name: "default", RequestsPerSecond: 10, Burst: 5, ConnectionsPerIP: 10},
		},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "limit_req zone=") || strings.Contains(out, "limit_req_zone") {
		t.Fatal("IP rate limits must not apply without trusted proxies")
	}
}

func TestRejectInjection(t *testing.T) {
	h := models.ProxyHost{
		PrimaryDomain:  "evil.com; return 200;",
		UpstreamScheme: "http",
		UpstreamHost:   "ok.example.com",
		UpstreamPort:   80,
		PathPrefix:     "/",
		Enabled:        true,
	}
	if err := ValidateHost(h); err == nil {
		t.Fatal("expected invalid domain to fail")
	}
}

func TestRejectMetadataUpstream(t *testing.T) {
	h := models.ProxyHost{
		PrimaryDomain:  "app.example.com",
		UpstreamScheme: "http",
		UpstreamHost:   "169.254.169.254",
		UpstreamPort:   80,
		PathPrefix:     "/",
		Enabled:        true,
	}
	if err := ValidateHost(h); err == nil {
		t.Fatal("expected metadata host to be blocked")
	}
}

func TestTLSAndACMEChallenge(t *testing.T) {
	certID := uuid.New()
	in := RenderInput{
		ACMEWebRoot: "/var/lib/nsp/acme-www",
		Hosts: []models.ProxyHost{{
			PrimaryDomain:    "secure.example.com",
			UpstreamScheme:   "http",
			UpstreamHost:     "backend.example.com",
			UpstreamPort:     80,
			PathPrefix:       "/",
			Enabled:          true,
			ForceHTTPS:       true,
			CertificateID:    &certID,
			AccessLogEnabled: true,
		}},
		Certs: map[string]TLSPaths{
			certID.String(): {CertPath: "/var/lib/nsp/certs/x/fullchain.pem", KeyPath: "/var/lib/nsp/certs/x/privkey.pem"},
		},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"listen 443 ssl;",
		"http2 on;",
		"ssl_protocols       TLSv1.2 TLSv1.3;",
		"ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256",
		"ssl_certificate     /var/lib/nsp/certs/x/fullchain.pem;",
		"/.well-known/acme-challenge/",
		"return 301 https://$host$request_uri;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// Self-signed / unknown chain: no OCSP (avoids nginx warn spam)
	if strings.Contains(out, "ssl_stapling") {
		t.Fatal("OCSP stapling must be off when TLSPaths.OCSP is false")
	}
}

func TestAccessLogFormatJSON(t *testing.T) {
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "fmt.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.example.com", UpstreamPort: 80, PathPrefix: "/",
			Enabled: true, AccessLogEnabled: true, AccessLogFormat: "json",
		}},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "log_format nsp_json escape=json") {
		t.Fatal("missing nsp_json log_format")
	}
	if !strings.Contains(out, " nsp_json;") {
		t.Fatalf("expected access_log … nsp_json; got:\n%s", out)
	}
}

func TestPerHostErrorLog(t *testing.T) {
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "err.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.example.com", UpstreamPort: 80, PathPrefix: "/",
			Enabled: true, AccessLogEnabled: true, ErrorLogEnabled: true,
		}},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "error_log /data/logs/nginx/error.log warn;") {
		t.Fatal("missing global error_log")
	}
	wantHost := "error_log /data/logs/nginx/proxy_host_error/err_example_com.log warn;"
	if !strings.Contains(out, wantHost) {
		t.Fatalf("missing per-host error_log; got:\n%s", out)
	}
	in.Hosts[0].ErrorLogEnabled = false
	outOff, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(outOff, "proxy_host_error/") {
		t.Fatal("per-host error_log must be omitted when disabled")
	}
}

func TestOCSPStaplingForACME(t *testing.T) {
	certID := uuid.New()
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain: "acme.example.com", UpstreamScheme: "http",
			UpstreamHost: "backend.example.com", UpstreamPort: 80, PathPrefix: "/",
			Enabled: true, CertificateID: &certID, ListenHTTP: true, ListenHTTPS: true, HTTP2: true,
		}},
		Certs: map[string]TLSPaths{
			certID.String(): {
				CertPath: "/var/lib/nsp/certs/y/fullchain.pem",
				KeyPath:  "/var/lib/nsp/certs/y/privkey.pem",
				OCSP:     true,
			},
		},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssl_stapling on;", "ssl_trusted_certificate /var/lib/nsp/certs/y/fullchain.pem;"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDisabledHostOmitted(t *testing.T) {
	in := RenderInput{Hosts: []models.ProxyHost{{
		PrimaryDomain:  "off.example.com",
		UpstreamScheme: "http",
		UpstreamHost:   "backend.example.com",
		UpstreamPort:   80,
		PathPrefix:     "/",
		Enabled:        false,
	}}}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "off.example.com") {
		t.Fatal("disabled host must not appear in config")
	}
}

func TestLBAlgorithmsGolden(t *testing.T) {
	cases := []struct {
		algo string
		want string
	}{
		{"round_robin", "server a.example.com:8080"},
		{"weighted_round_robin", "weight=5"},
		{"least_conn", "least_conn;"},
		{"ip_hash", "ip_hash;"},
		{"hash", "hash $request_uri;"},
		{"hash_consistent", "hash $request_uri consistent;"},
	}
	for _, tc := range cases {
		t.Run(tc.algo, func(t *testing.T) {
			id := uuid.New()
			u := models.Upstream{
				ID: id, Name: "pool-" + tc.algo, Algorithm: tc.algo,
				HashKey: "$request_uri", Scheme: "http",
				ConnectTimeout: "5s", SendTimeout: "60s", ReadTimeout: "60s",
				MaxFails: 3, FailTimeout: "10s",
				Members: []models.UpstreamMember{
					{Host: "a.example.com", Port: 8080, Weight: 5},
					{Host: "b.example.com", Port: 8080, Weight: 1, IsBackup: true},
				},
			}
			block, err := RenderPoolUpstream(u)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(block, tc.want) {
				t.Fatalf("missing %q in:\n%s", tc.want, block)
			}
			if !strings.Contains(block, "max_fails=3 fail_timeout=10s") {
				t.Fatalf("missing passive health in:\n%s", block)
			}
			if tc.algo != "ip_hash" && !strings.Contains(block, "backup") {
				t.Fatalf("missing backup in:\n%s", block)
			}
		})
	}
}

func TestLBDrainAndHTTPSNI(t *testing.T) {
	poolID := uuid.New()
	u := models.Upstream{
		ID: poolID, Name: "secure-pool", Algorithm: "round_robin",
		Scheme: "https", SNI: "origin.example.com",
		ConnectTimeout: "3s", SendTimeout: "30s", ReadTimeout: "30s",
		MaxFails: 2, FailTimeout: "5s", HashKey: "$request_uri",
		Members: []models.UpstreamMember{
			{Host: "n1.example.com", Port: 443, Weight: 1, MaxConns: 50},
			{Host: "n2.example.com", Port: 443, Weight: 1, IsDrain: true},
		},
	}
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			PrimaryDomain:  "app.example.com",
			UpstreamScheme: "https",
			UpstreamHost:   "pool.local",
			UpstreamPort:   80,
			PathPrefix:     "/",
			Enabled:        true,
			UpstreamID:     &poolID,
		}},
		Upstreams: map[string]models.Upstream{poolID.String(): u},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"proxy_ssl_server_name on;",
		"proxy_ssl_name origin.example.com;",
		"proxy_connect_timeout 3s;",
		"proxy_next_upstream error timeout",
		"n2.example.com:443",
		" down;",
		"max_conns=50",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRejectBlockedMember(t *testing.T) {
	err := ValidateMember(models.UpstreamMember{Host: "169.254.169.254", Port: 80, Weight: 1})
	if err == nil {
		t.Fatal("expected metadata member blocked")
	}
}
