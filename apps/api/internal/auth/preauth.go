package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const preAuthPrefix = "nsp:preauth:"

type PreAuth struct {
	Token     string    `json:"token"`
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *SessionStore) SavePreAuth(ctx context.Context, userID uuid.UUID, email string, ttl time.Duration) (PreAuth, error) {
	tok, err := RandomToken(24)
	if err != nil {
		return PreAuth{}, err
	}
	p := PreAuth{
		Token:     tok,
		UserID:    userID,
		Email:     email,
		ExpiresAt: time.Now().Add(ttl),
	}
	b, err := json.Marshal(p)
	if err != nil {
		return PreAuth{}, err
	}
	if err := s.RDB.Set(ctx, preAuthPrefix+tok, b, ttl).Err(); err != nil {
		return PreAuth{}, err
	}
	return p, nil
}

func (s *SessionStore) ConsumePreAuth(ctx context.Context, token string) (PreAuth, error) {
	var p PreAuth
	key := preAuthPrefix + token
	b, err := s.RDB.Get(ctx, key).Bytes()
	if err != nil {
		return p, err
	}
	_ = s.RDB.Del(ctx, key)
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if time.Now().After(p.ExpiresAt) {
		return p, fmt.Errorf("preauth expired")
	}
	return p, nil
}
