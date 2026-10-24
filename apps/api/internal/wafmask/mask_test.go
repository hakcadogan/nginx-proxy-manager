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
