package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/pquerna/otp/totp"
)

// GenerateMFASecret creates a TOTP secret for enrollment (REQ-AUTH-007).
func GenerateMFASecret(email, issuer string) (secret, otpauthURL string, qrPNGBase64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
	})
	if err != nil {
		return "", "", "", err
	}
	img, err := key.Image(200, 200)
	if err != nil {
		return key.Secret(), key.URL(), "", err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return key.Secret(), key.URL(), "", err
	}
	return key.Secret(), key.URL(), base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func ValidateTOTP(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	return totp.Validate(code, secret)
}

func MFAIssuer() string {
	return "Nginx Security Platform"
}

func FormatOTPAuth(secret, email string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		MFAIssuer(), email, secret, MFAIssuer())
}
