package nginxcfg

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestRenderModSecOverlay(t *testing.T) {
	polID := uuid.New()
	hostID := uuid.New()
	out, err := RenderModSecOverlay(WAFRenderInput{
		Global: models.WAFPolicy{
			EngineMode: "DetectionOnly", ParanoiaLevel: 2, AuditRelevantOnly: true, Enabled: true,
		},
		Exceptions: []models.WAFException{
			{
				ID: uuid.New(), PolicyID: polID, RuleID: "942100", PathPrefix: "/api/legacy", Reason: "fp", Enabled: true,
			},
			{
				ID: uuid.New(), PolicyID: polID, HostID: &hostID, RuleID: "1100200",
				PathPrefix: "/admin", Reason: "scoped", Enabled: true,
			},
		},
		HostDomains: map[string]string{hostID.String(): "behice.local"},
		CRSVersion:  "4.20.0",
		UAAllowlist: []string{"Googlebot", "MyMonitor/1.0"},
		IPAllowlist: []string{"203.0.113.10", "10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"id:10900000",
		"blocking_paranoia_level=2",
		"detection_paranoia_level=2",
		"inbound_anomaly_score_threshold=5",
		"bad-bots.txt",
		"ua-allowlist.txt",
		"ip-allowlist.txt",
		"id:1000080",
		"ctl:ruleEngine=Off",
		"@ipMatchFromFile",
		"id:1000090",
		"skipAfter:END_NSP_BAD_BOT",
		"SecMarker END_NSP_BAD_BOT",
		"ctl:ruleRemoveById=942100",
		"/api/legacy",
		`SecRule REQUEST_HEADERS:Host "@rx ^behice\.local(?::\d+)?$"`,
		`"id:1001001,phase:1,pass,nolog,chain"`,
		`SecRule REQUEST_URI "@beginsWith /admin"`,
		`ctl:ruleRemoveById=1100200`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderModSecOverlayEnvExceptionAlsoRemovesCustomBlock(t *testing.T) {
	polID := uuid.New()
	hostID := uuid.New()
	out, err := RenderModSecOverlay(WAFRenderInput{
		Global: models.WAFPolicy{
			EngineMode: "On", ParanoiaLevel: 1, AuditRelevantOnly: true, Enabled: true,
		},
		Exceptions: []models.WAFException{{
			ID: uuid.New(), PolicyID: polID, HostID: &hostID, RuleID: "930130",
			PathPrefix: "/.env", Reason: "allow env path", Enabled: true,
		}},
		HostDomains: map[string]string{hostID.String(): "behice.local"},
		CustomRules: CustomRulesBundle{Global: DefaultGlobalCustomRules},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ctl:ruleRemoveById=930130`,
		`ctl:ruleRemoveByTag=nsp/block-dotenv`,
		`ctl:ruleRemoveById=1100500`, // discovered from custom snippet, not a hardcoded constant path
		`@beginsWith /.env`,
		`tag:'nsp/block-dotenv'`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `REQUEST_URI "@beginsWith`) && strings.Contains(out, `Host "@rx`) {
		// must not join two SecRule targets with a comma on one line
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "SecRule") && strings.Contains(line, "REQUEST_HEADERS:Host") && strings.Contains(line, "REQUEST_URI") {
				t.Fatalf("invalid comma-joined SecRule: %s", line)
			}
		}
	}
}

func TestRenderModSecOverlayDisabledRules(t *testing.T) {
	out, err := RenderModSecOverlay(WAFRenderInput{
		Global: models.WAFPolicy{
			EngineMode: "DetectionOnly", ParanoiaLevel: 1, AuditRelevantOnly: true, Enabled: true,
		},
		DisabledRules: []string{"942100", "941100", "942100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "SecRuleRemoveById 941100") || !strings.Contains(out, "SecRuleRemoveById 942100") {
		t.Fatalf("disabled rules missing:\n%s", out)
	}
	if strings.Count(out, "SecRuleRemoveById 942100") != 1 {
		t.Fatalf("expected dedupe of 942100:\n%s", out)
	}
}

func TestValidateUAAllowlist(t *testing.T) {
	if err := ValidateUAAllowlistPatterns([]string{"Googlebot", "curl/"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUAAllowlistPatterns([]string{`evil";id:1`}); err == nil {
		t.Fatal("expected reject")
	}
	f := FormatUAAllowlistFile([]string{" Googlebot ", "Googlebot", "bingbot"})
	if !strings.Contains(f, "Googlebot\n") || strings.Count(f, "Googlebot") != 1 {
		t.Fatalf("normalize failed: %s", f)
	}
}

func TestValidateIPAllowlist(t *testing.T) {
	if err := ValidateIPAllowlistEntries([]string{"203.0.113.10", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIPAllowlistEntries([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected reject")
	}
	got := NormalizeIPAllowlist([]string{" 10.0.0.1 ", "10.0.0.1", "10.0.0.0/8"})
	if len(got) != 2 {
		t.Fatalf("normalize: %v", got)
	}
	f := FormatIPAllowlistFile(got)
	if !strings.Contains(f, "10.0.0.1\n") || !strings.Contains(f, "10.0.0.0/8") {
		t.Fatalf("file: %s", f)
	}
	out, err := RenderModSecOverlay(WAFRenderInput{
		Global:      models.WAFPolicy{EngineMode: "On", ParanoiaLevel: 1, Enabled: true},
		IPAllowlist: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "id:1000080") {
		t.Fatal("empty IP allowlist must not emit rule")
	}
}

func TestHostEngineDirective(t *testing.T) {
	g := models.WAFPolicy{Enabled: true, EngineMode: "DetectionOnly"}
	d := HostEngineDirective(true, g, nil)
	if !strings.Contains(d, "modsecurity on;") || !strings.Contains(d, "engine-DetectionOnly.conf") {
		t.Fatalf("bad directive: %s", d)
	}
	block := HostEngineDirective(true, models.WAFPolicy{Enabled: true, EngineMode: "On"}, nil)
	if !strings.Contains(block, "engine-On.conf") {
		t.Fatalf("blocking missing: %s", block)
	}
	off := HostEngineDirective(false, g, nil)
	if !strings.Contains(off, "modsecurity off;") {
		t.Fatalf("expected off: %s", off)
	}
}

func TestWAFInRender(t *testing.T) {
	hostID := uuid.New()
	in := RenderInput{
		Hosts: []models.ProxyHost{{
			ID: hostID, PrimaryDomain: "waf.example.com",
			UpstreamScheme: "http", UpstreamHost: "example.com", UpstreamPort: 80,
			PathPrefix: "/", Enabled: true, WAFEnabled: true,
		}},
		WAF: &WAFRenderInput{
			Global: models.WAFPolicy{Enabled: true, EngineMode: "DetectionOnly", ParanoiaLevel: 1},
		},
	}
	out, _, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"load_module modules/ngx_http_modsecurity_module.so;",
		"modsecurity on;",
		"modsecurity_rules_file /etc/nginx/modsec/engine-DetectionOnly.conf;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
