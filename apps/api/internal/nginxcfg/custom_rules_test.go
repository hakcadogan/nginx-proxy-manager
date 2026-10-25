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

func TestCustomRuleIDsMatchingEnvDiscoversRenumberedID(t *testing.T) {
	bundle := CustomRulesBundle{
		Global: `SecRule REQUEST_URI "@rx (?i)\.env" \
    "id:1199999,phase:1,deny,status:403,log,msg:'block env',tag:'nsp/block-dotenv'"`,
	}
	ids := CustomRuleIDsMatchingEnv(bundle)
	if len(ids) != 1 || ids[0] != "1199999" {
		t.Fatalf("ids=%v want [1199999]", ids)
	}
}
