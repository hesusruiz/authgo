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

// SessionEntry holds the WebAuthn session data along with the authenticated user
// and its exact expiration time to facilitate cache eviction.
type SessionEntry struct {
	WASession *webauthn.SessionData
	User      *User
	ExpiresAt time.Time
}

// SessionStore provides a thread-safe, in-memory storage mechanism for WebAuthn sessions,
// tying them to secure HTTP cookies.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]SessionEntry
	stopChan chan struct{}
}

// NewSessionStore initializes and returns a new empty SessionStore, starting a background
// ticker to evict expired sessions periodically.
func NewSessionStore() *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]SessionEntry),
		stopChan: make(chan struct{}),
	}
	go s.startEvictionWorker(1 * time.Minute)
	return s
}

// Close cleanly terminates the background session eviction worker.
func (s *SessionStore) Close() {
	close(s.stopChan)
}

// startEvictionWorker runs a periodic loop executing session eviction at the specified interval
// until Close() is called.
func (s *SessionStore) startEvictionWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			s.evictExpired()
		case <-s.stopChan:
			ticker.Stop()
			return
		}
	}
}

// evictExpired scans the session map and safely deletes any entries whose
// expiration timestamp has passed. It relies on locking the store instance.
func (s *SessionStore) evictExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.sessions {
		if now.After(entry.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

const sessionCookieName = "__Host-webauthn_session"

// CreateSession creates a new session ID, stores the sessionData with the given
// expiration time, and sets a secure HttpOnly cookie on the response. If expireSeconds
// is 0, a default of 5 minutes is used.
func (s *SessionStore) CreateSession(w http.ResponseWriter, sessionData *webauthn.SessionData, user *User, expireSeconds int) (string, error) {
	if expireSeconds <= 0 {
		expireSeconds = 300 // 5 minutes default
	}
	expiresAt := time.Now().Add(time.Duration(expireSeconds) * time.Second)

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sessionID := base64.URLEncoding.EncodeToString(b)

	s.mu.Lock()
	s.sessions[sessionID] = SessionEntry{
		WASession: sessionData,
		User:      user,
		ExpiresAt: expiresAt,
	}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   expireSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return sessionID, nil
}

// GetSession retrieves the SessionEntry mapped to the cookie found
// in the HTTP request.
func (s *SessionStore) GetSession(r *http.Request) (SessionEntry, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return SessionEntry{}, err
	}

	s.mu.RLock()
	entry, ok := s.sessions[cookie.Value]
	s.mu.RUnlock()

	if !ok {
		return SessionEntry{}, fmt.Errorf("session not found")
	}
	return entry, nil
}

// DeleteSession deletes the session mapping from memory based on the cookie found
// in the request, and sets an expired cookie on the response to delete it from the client.
func (s *SessionStore) DeleteSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
