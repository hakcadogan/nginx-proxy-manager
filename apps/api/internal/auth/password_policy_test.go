package auth

import "testing"

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Fatal("expected min length error")
	}
	if err := ValidatePassword("onlylettersxx"); err == nil {
		t.Fatal("expected digit requirement")
	}
	if err := ValidatePassword("123456789012"); err == nil {
		t.Fatal("expected letter requirement")
	}
	if err := ValidatePassword("goodpass1234"); err != nil {
		t.Fatal(err)
	}
}
