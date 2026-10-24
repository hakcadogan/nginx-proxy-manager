package auth

import (
	"fmt"
	"unicode"
)

// ValidatePassword enforces P06 password policy (REQ-AUTH-006).
func ValidatePassword(pw string) error {
	if len(pw) < 12 {
		return fmt.Errorf("password min 12 characters")
	}
	var letter, digit bool
	for _, r := range pw {
		switch {
		case unicode.IsLetter(r):
			letter = true
		case unicode.IsDigit(r):
			digit = true
		}
	}
	if !letter || !digit {
		return fmt.Errorf("password must include letters and digits")
	}
	return nil
}
