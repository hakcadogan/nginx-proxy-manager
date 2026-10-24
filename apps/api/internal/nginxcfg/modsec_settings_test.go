package nginxcfg

import (
	"strings"
	"testing"
)

func TestModSecGlobalSettingsRender(t *testing.T) {
	s := DefaultModSecGlobalSettings()
	s.DebugLogLevel = 1
	s.AuditLogParts = "ABCEFHIZ"
	out, err := RenderModSecGlobalSettings(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SecAuditEngine RelevantOnly",
		"SecDebugLogLevel 1",
		"SecAuditLogParts ABCEFHIZ",
		"SecRequestBodyAccess On",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestCustomRulesValidateAndRender(t *testing.T) {
	if err := ValidateCustomRulesText(`SecRule REQUEST_URI "@streq /x" "id:1100100,phase:1,deny,status:403"`); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCustomRulesText(DefaultGlobalCustomRules); err != nil {
		t.Fatalf("default .env rule: %v", err)
	}
	if err := ValidateCustomRulesText(`SecRule REQUEST_URI "@rx evaluate" "id:1100999,phase:1,pass,nolog"`); err != nil {
		t.Fatalf("evaluate must not trip lua filter: %v", err)
	}
	if err := ValidateCustomRulesText(`Include /etc/passwd`); err == nil {
		t.Fatal("expected reject Include")
	}
	out, err := RenderCustomRules(CustomRulesBundle{
		Global: `SecAction "id:1100200,phase:1,pass,nolog"`,
		Hosts: map[string]string{
			"h1": `SecRule REQUEST_URI "@streq /admin" "id:1100300,phase:1,deny,status:403"`,
		},
	}, map[string]string{"h1": "app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "custom rules (global)") || !strings.Contains(out, "app.example.com") || !strings.Contains(out, "skipAfter:") {
		t.Fatalf("bad render: %s", out)
	}
}
