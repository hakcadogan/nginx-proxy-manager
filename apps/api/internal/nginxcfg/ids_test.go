package nginxcfg

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestRenderIPAccessAllowlistWins(t *testing.T) {
	out, err := RenderIPAccess([]models.IPPolicy{
		{ID: uuid.New(), Kind: "allow", IPCIDR: "203.0.113.10", Source: "manual"},
		{ID: uuid.New(), Kind: "ban", IPCIDR: "203.0.113.10", Source: "crowdsec"},
		{ID: uuid.New(), Kind: "deny", IPCIDR: "198.51.100.5", Source: "manual"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "allow 203.0.113.10;") {
		t.Fatalf("missing allow: %s", out)
	}
	if strings.Contains(out, "deny 203.0.113.10;") {
		t.Fatalf("allowlisted IP must not be denied: %s", out)
	}
	if !strings.Contains(out, "deny 198.51.100.5;") {
		t.Fatalf("missing deny: %s", out)
	}
}

func TestValidateIPCIDR(t *testing.T) {
	if err := ValidateIPCIDR("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIPCIDR("10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIPCIDR("not-an-ip"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderIPAccessPassive(t *testing.T) {
	out, err := RenderIPAccessMode([]models.IPPolicy{
		{ID: uuid.New(), Kind: "deny", IPCIDR: "198.51.100.5", Source: "crowdsec"},
		{ID: uuid.New(), Kind: "ban", IPCIDR: "203.0.113.9", Source: "manual"},
	}, "passive")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "    deny ") {
		t.Fatalf("passive must not emit deny directive: %s", out)
	}
	if !strings.Contains(out, "passive") {
		t.Fatalf("expected passive comment: %s", out)
	}
}
