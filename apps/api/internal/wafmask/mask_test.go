package wafmask

import "testing"

func TestMaskSecrets(t *testing.T) {
	in := `user=alice&password=super-secret-12&Authorization=Bearer abc.def.ghi`
	out := Mask(in)
	if contains(out, "super-secret") || contains(out, "abc.def") {
		t.Fatalf("secret leaked: %s", out)
	}
	if !contains(out, "***") {
		t.Fatalf("expected mask markers: %s", out)
	}
}

func TestMaskPreservesIPv4(t *testing.T) {
	in := "client 203.0.113.118 hit rule"
	out := Mask(in)
	if out != in {
		t.Fatalf("IPv4 must not be JWT-masked: got %q", out)
	}
}

func TestMaskMapPreservesClientIP(t *testing.T) {
	m := map[string]any{
		"client_ip": "198.51.100.42",
		"uri":       "/?token=eyJhbGciOi.payload.sig",
	}
	MaskMap(m)
	if m["client_ip"] != "198.51.100.42" {
		t.Fatalf("client_ip=%v", m["client_ip"])
	}
	if contains(m["uri"].(string), "eyJhbGciOi") {
		t.Fatalf("jwt leaked in uri: %v", m["uri"])
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
