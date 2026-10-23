package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"
)

const SessionTTL = 24 * time.Hour

func newSessionToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validSessionToken(token string) bool {
	if len(token) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32
}

func (s *Store) CreateSession(ctx context.Context, userID int64) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO sessions(token, user_id) VALUES($1,$2)`, token, userID)
	if err != nil {
		return "", mapErr(err)
	}
	return token, nil
}

func (s *Store) UserIDBySession(ctx context.Context, token string) (int64, error) {
	if !validSessionToken(token) {
		return 0, ErrNotFound
	}
	var userID int64
	err := s.Pool.QueryRow(ctx,
		`SELECT user_id FROM sessions
		 WHERE token=$1 AND created_at >= now() - interval '24 hours'`, token).
		Scan(&userID)
	if err != nil {
		return 0, mapErr(err)
	}
	return userID, nil
}
