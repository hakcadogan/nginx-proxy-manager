package nginxcfg

import "testing"

func TestValidateCustomRulesContinuationMidQuote(t *testing.T) {
	body := `SecRule REQUEST_URI|ARGS|REQUEST_HEADERS "@rx (?i)(?:^|[/?])\.env(?:$|[/?&#])" \
    "id:1100500,phase:1,deny,status:403,log,msg:'NSP block .env access'"
SecRule ARGS_NAMES|ARGS_POST_NAMES|FILES_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1100618,phase:2,t:none,deny,status:403,log,\
    msg:'php2shell mitigation CVE-2026-109618/109619'"`
	if err := ValidateCustomRulesText(body); err != nil {
		t.Fatalf("expected valid multi-line rules: %v", err)
	}
}

func TestValidateCustomRulesRejectInclude(t *testing.T) {
	body := "SecRule REQUEST_URI \"@rx .\" \"id:1,phase:1,pass\"\nInclude /etc/evil.conf"
	if err := ValidateCustomRulesText(body); err == nil {
		t.Fatal("expected Include rejected")
	}
}

func TestValidateCustomRulesRejectBareLine(t *testing.T) {
	if err := ValidateCustomRulesText("msg:'orphan'"); err == nil {
		t.Fatal("expected bare action line rejected")
	}
}
