package wafingest

import (
	"testing"
)

func TestParseAuditLine_HostHeaderCase(t *testing.T) {
	line := `{"transaction":{"client_ip":"1.2.3.4","unique_id":"u1","request":{"method":"GET","uri":"/?id=1","headers":{"Host":"behice.local:8080","User-Agent":"curl"}},"messages":[{"message":"SQL Injection","details":{"ruleId":"942100","severity":"CRITICAL","data":"Matched Data"}}]}}`
	ev, ok := parseAuditLine(line)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if ev.Domain != "behice.local" {
		t.Fatalf("domain=%q want behice.local (strip port, Host capital H)", ev.Domain)
	}
	if ev.ClientIP != "1.2.3.4" {
		t.Fatalf("client_ip=%q want full IPv4 (not JWT-masked)", ev.ClientIP)
	}
	if ev.RuleID != "942100" {
		t.Fatalf("rule=%q", ev.RuleID)
	}
	if ev.Method != "GET" {
		t.Fatalf("method=%q", ev.Method)
	}
}

func TestParseAuditLine_LowercaseHost(t *testing.T) {
	line := `{"transaction":{"request":{"method":"GET","uri":"/","headers":{"host":"app.example.com"}},"messages":[{"message":"x","details":{"ruleId":"941100"}}]}}`
	ev, ok := parseAuditLine(line)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if ev.Domain != "app.example.com" {
		t.Fatalf("domain=%q", ev.Domain)
	}
}

func TestParseAuditLine_NoMessages(t *testing.T) {
	line := `{"transaction":{"request":{"uri":"/","headers":{"Host":"x"}},"messages":[]}}`
	if _, ok := parseAuditLine(line); ok {
		t.Fatal("empty messages should be skipped")
	}
}
