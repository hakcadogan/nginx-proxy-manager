package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (REQ-AUTH-001).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	// argon2id v=19 m=...,t=...,p=... salt hash
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var memory uint32
	var timeCost uint32
	var threads uint8
	param := parts[2]
	for _, kv := range strings.Split(param, ",") {
		p := strings.SplitN(kv, "=", 2)
		if len(p) != 2 {
			return false
		}
		switch p[0] {
		case "m":
			v, err := strconv.ParseUint(p[1], 10, 32)
			if err != nil {
				return false
			}
			memory = uint32(v)
		case "t":
			v, err := strconv.ParseUint(p[1], 10, 32)
			if err != nil {
				return false
			}
			timeCost = uint32(v)
		case "p":
			v, err := strconv.ParseUint(p[1], 10, 8)
			if err != nil {
				return false
			}
			threads = uint8(v)
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	if len(got) != len(want) {
		return false
	}
	var diff byte
	for i := range got {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}

func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
