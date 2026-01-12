// internal/session/session_store.go
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	DeviceInfo   string    `json:"device_info"`
	CreatedAt    time.Time `json:"created_at"`
	LastActive   time.Time `json:"last_active"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type SessionStore struct {
	client *redis.Client
	ctx    context.Context
}

func NewSessionStore(client *redis.Client) *SessionStore {
	return &SessionStore{
		client: client,
		ctx:    context.Background(),
	}
}

func (s *SessionStore) Create(session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	
	key := fmt.Sprintf("session:%s:%s", session.UserID, session.ID)
	expiration := time.Until(session.ExpiresAt)
	
	return s.client.Set(s.ctx, key, data, expiration).Err()
}

func (s *SessionStore) Get(userID, sessionID string) (*Session, error) {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	
	data, err := s.client.Get(s.ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	
	var session Session
	err = json.Unmarshal(data, &session)
	return &session, err
}

func (s *SessionStore) UpdateLastActive(userID, sessionID string) error {
	session, err := s.Get(userID, sessionID)
	if err != nil {
		return err
	}
	
	session.LastActive = time.Now()
	return s.Create(session)
}

func (s *SessionStore) Delete(userID, sessionID string) error {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	return s.client.Del(s.ctx, key).Err()
}

func (s *SessionStore) DeleteAll(userID string) error {
	pattern := fmt.Sprintf("session:%s:*", userID)
	
	keys, err := s.client.Keys(s.ctx, pattern).Result()
	if err != nil {
		return err
	}
	
	if len(keys) > 0 {
		return s.client.Del(s.ctx, keys...).Err()
	}
	
	return nil
}

func (s *SessionStore) GetUserSessions(userID string) ([]Session, error) {
	pattern := fmt.Sprintf("session:%s:*", userID)
	
	keys, err := s.client.Keys(s.ctx, pattern).Result()
	if err != nil {
		return nil, err
	}
	
	var sessions []Session
	for _, key := range keys {
		data, err := s.client.Get(s.ctx, key).Bytes()
		if err == nil {
			var session Session
			if json.Unmarshal(data, &session) == nil {
				sessions = append(sessions, session)
			}
		}
	}
	
	return sessions, nil
}