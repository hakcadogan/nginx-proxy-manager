package nginxcfg

import "testing"

func TestIsProtectedIP(t *testing.T) {
	csv := "127.0.0.1,::1,10.20.0.0/16"
	if !IsProtectedIP("127.0.0.1", csv) {
		t.Fatal("loopback should be protected")
	}
	if !IsProtectedIP("10.20.5.9", csv) {
		t.Fatal("CIDR member should be protected")
	}
	if IsProtectedIP("203.0.113.10", csv) {
		t.Fatal("public IP must not be protected")
	}
	if err := ValidateProtectedBan("127.0.0.1", csv); err == nil {
		t.Fatal("expected ban of loopback to fail")
	}
}
