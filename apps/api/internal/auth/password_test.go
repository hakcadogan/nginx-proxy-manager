package auth

import (
	"testing"

	"github.com/nginx-proxy-waf/api/internal/models"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct-horse-battery") {
		t.Fatal("expected password to verify")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("expected wrong password to fail")
	}
	if hash == "correct-horse-battery" {
		t.Fatal("password must not be stored plaintext")
	}
}

func TestRBACMatrix(t *testing.T) {
	cases := []struct {
		role models.Role
		perm Permission
		want bool
	}{
		{models.RoleAdmin, PermUsersWrite, true},
		{models.RoleOperator, PermUsersWrite, false},
		{models.RoleViewer, PermHostsWrite, false},
		{models.RoleViewer, PermHostsRead, true},
		{models.RoleOperator, PermConfigWrite, true},
		{models.RoleViewer, PermConfigWrite, false},
	}
	for _, tc := range cases {
		got := HasPermission(tc.role, tc.perm)
		if got != tc.want {
			t.Fatalf("%s %s: got %v want %v", tc.role, tc.perm, got, tc.want)
		}
	}
}
