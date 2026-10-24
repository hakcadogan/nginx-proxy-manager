package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/redis/go-redis/v9"
)

const sessionKeyPrefix = "nsp:session:"

type SessionStore struct {
	RDB *redis.Client
	TTL time.Duration
}

func (s *SessionStore) Save(ctx context.Context, sess models.Session) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.RDB.Set(ctx, sessionKeyPrefix+sess.ID, b, s.TTL).Err()
}

func (s *SessionStore) Get(ctx context.Context, id string) (models.Session, error) {
	var sess models.Session
	b, err := s.RDB.Get(ctx, sessionKeyPrefix+id).Bytes()
	if err != nil {
		return sess, err
	}
	if err := json.Unmarshal(b, &sess); err != nil {
		return sess, err
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.Delete(ctx, id)
		return sess, fmt.Errorf("session expired")
	}
	return sess, nil
}

func (s *SessionStore) Delete(ctx context.Context, id string) error {
	return s.RDB.Del(ctx, sessionKeyPrefix+id).Err()
}

func NewSession(user models.User, ttl time.Duration) (models.Session, error) {
	sid, err := RandomToken(32)
	if err != nil {
		return models.Session{}, err
	}
	csrf, err := RandomToken(32)
	if err != nil {
		return models.Session{}, err
	}
	return models.Session{
		ID:        sid,
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}
