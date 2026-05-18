package passkeys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// sessionEntry holds the webauthn session data along with its exact expiration
// time to facilitate cache eviction.
type sessionEntry struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

// SessionStore provides a thread-safe, in-memory storage mechanism for WebAuthn sessions,
// tying them to secure HTTP cookies.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
}

// NewSessionStore initializes and returns a new empty SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]sessionEntry),
	}
}

// evictExpired scans the session map and safely deletes any entries whose
// expiration timestamp has passed. It relies on locking the store instance.
func (s *SessionStore) evictExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.sessions {
		if now.After(entry.expiresAt) {
			delete(s.sessions, id)
		}
	}
}

// SaveSession creates a new session ID, stores the sessionData with the given
// expiration time, and sets a secure HttpOnly cookie on the response. If expireSeconds
// is 0, a default of 5 minutes is used.
func (s *SessionStore) SaveSession(w http.ResponseWriter, sessionData *webauthn.SessionData, expireSeconds int) error {
	s.evictExpired()

	if expireSeconds <= 0 {
		expireSeconds = 300 // 5 minutes default
	}
	expiresAt := time.Now().Add(time.Duration(expireSeconds) * time.Second)

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	sessionID := base64.URLEncoding.EncodeToString(b)

	s.mu.Lock()
	s.sessions[sessionID] = sessionEntry{
		data:      sessionData,
		expiresAt: expiresAt,
	}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   expireSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// GetSession retrieves the WebAuthn session data mapped to the cookie found
// in the HTTP request. It triggers eviction of expired items before looking up the session.
func (s *SessionStore) GetSession(r *http.Request) (*webauthn.SessionData, error) {
	s.evictExpired()

	cookie, err := r.Cookie("webauthn_session")
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	entry, ok := s.sessions[cookie.Value]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return entry.data, nil
}

// DeleteSession deletes the session mapping from memory based on the cookie found
// in the request, and sets an expired cookie on the response to delete it from the client.
func (s *SessionStore) DeleteSession(w http.ResponseWriter, r *http.Request) {
	s.evictExpired()

	cookie, err := r.Cookie("webauthn_session")
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
