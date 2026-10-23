package passkeys

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestSessionStore_CreateAndGetSession(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	user := &User{
		id:          []byte("user-1"),
		email:       "alice@example.com",
		displayName: "Alice",
	}
	sessionData := &webauthn.SessionData{
		Challenge: "test-challenge-123",
		UserID:    []byte("user-1"),
	}

	// 1. Test creation with default expiration (expireSeconds <= 0)
	rec := httptest.NewRecorder()
	sessionID, err := store.CreateSession(rec, sessionData, user, 0)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if sessionID == "" {
		t.Fatal("expected non-empty sessionID")
	}

	// Verify cookie set in response
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected cookie %q to be set in response", sessionCookieName)
	}
	if sessionCookie.Value != sessionID {
		t.Errorf("expected cookie value %q, got %q", sessionID, sessionCookie.Value)
	}
	if sessionCookie.Path != "/" {
		t.Errorf("expected cookie Path '/', got %q", sessionCookie.Path)
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("expected cookie HttpOnly to be true")
	}
	if !sessionCookie.Secure {
		t.Errorf("expected cookie Secure to be true")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected cookie SameSite Lax, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.MaxAge != 300 {
		t.Errorf("expected default MaxAge 300, got %d", sessionCookie.MaxAge)
	}

	// 2. Test GetSession with valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(sessionCookie)

	entry, err := store.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if entry.WASession == nil || entry.WASession.Challenge != "test-challenge-123" {
		t.Errorf("unexpected WASession in retrieved entry: %+v", entry.WASession)
	}
	if entry.User == nil || entry.User.email != "alice@example.com" {
		t.Errorf("unexpected User in retrieved entry: %+v", entry.User)
	}
	if time.Until(entry.ExpiresAt) > 300*time.Second || time.Until(entry.ExpiresAt) <= 0 {
		t.Errorf("unexpected ExpiresAt: %v", entry.ExpiresAt)
	}

	// 3. Test creation with custom expiration (e.g. 60 seconds)
	recCustom := httptest.NewRecorder()
	sessionIDCustom, err := store.CreateSession(recCustom, sessionData, user, 60)
	if err != nil {
		t.Fatalf("CreateSession with custom expiration failed: %v", err)
	}
	customCookies := recCustom.Result().Cookies()
	if len(customCookies) == 0 || customCookies[0].MaxAge != 60 {
		t.Errorf("expected custom MaxAge 60, got %v", customCookies)
	}
	if sessionIDCustom == sessionID {
		t.Errorf("expected unique session IDs, got duplicate: %s", sessionID)
	}
}

func TestSessionStore_GetSession_NotFoundAndMissingCookie(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	// 1. Request without cookie
	reqWithoutCookie := httptest.NewRequest(http.MethodGet, "/profile", nil)
	_, err := store.GetSession(reqWithoutCookie)
	if err == nil {
		t.Fatal("expected error when cookie is missing, got nil")
	}

	// 2. Request with non-existent session cookie
	reqWithBadCookie := httptest.NewRequest(http.MethodGet, "/profile", nil)
	reqWithBadCookie.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "non-existent-session-id",
	})
	_, err = store.GetSession(reqWithBadCookie)
	if err == nil {
		t.Fatal("expected error for non-existent session ID, got nil")
	}
	if err.Error() != "session not found" {
		t.Errorf("expected 'session not found' error, got %q", err.Error())
	}
}

func TestSessionStore_DeleteSession(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	user := &User{email: "bob@example.com"}
	sessionData := &webauthn.SessionData{Challenge: "delete-test"}

	recCreate := httptest.NewRecorder()
	sessionID, err := store.CreateSession(recCreate, sessionData, user, 300)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Confirm session is retrievable
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionID,
	})
	if _, err := store.GetSession(req); err != nil {
		t.Fatalf("GetSession before delete failed: %v", err)
	}

	// Delete the session
	recDelete := httptest.NewRecorder()
	store.DeleteSession(recDelete, req)

	// Check that session is removed from store
	if _, err := store.GetSession(req); err == nil {
		t.Fatal("expected session to be deleted, but GetSession succeeded")
	}

	// Check response cookie to ensure client-side cookie deletion
	cookies := recDelete.Result().Cookies()
	var deleteCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			deleteCookie = c
			break
		}
	}
	if deleteCookie == nil {
		t.Fatalf("expected deletion cookie %q to be set in response", sessionCookieName)
	}
	if deleteCookie.Value != "" {
		t.Errorf("expected empty value for deletion cookie, got %q", deleteCookie.Value)
	}
	if deleteCookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1 for deletion cookie, got %d", deleteCookie.MaxAge)
	}
}

func TestSessionStore_DeleteSession_NoCookieInRequest(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// Calling DeleteSession on request with no cookie should not panic
	store.DeleteSession(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected deletion cookie even when request lacked cookie")
	}
	if cookies[0].MaxAge != -1 || cookies[0].Value != "" {
		t.Errorf("expected expired cookie, got %+v", cookies[0])
	}
}

func TestSessionStore_EvictExpired(t *testing.T) {
	store := &SessionStore{
		sessions: make(map[string]SessionEntry),
		stopChan: make(chan struct{}),
	}
	// Note: not starting worker to test evictExpired directly

	now := time.Now()
	// Expired session
	store.sessions["expired1"] = SessionEntry{
		ExpiresAt: now.Add(-10 * time.Second),
	}
	// Another expired session
	store.sessions["expired2"] = SessionEntry{
		ExpiresAt: now.Add(-1 * time.Second),
	}
	// Active session
	store.sessions["active1"] = SessionEntry{
		ExpiresAt: now.Add(60 * time.Second),
	}

	store.evictExpired()

	if len(store.sessions) != 1 {
		t.Fatalf("expected 1 session remaining after eviction, got %d", len(store.sessions))
	}
	if _, ok := store.sessions["active1"]; !ok {
		t.Errorf("expected 'active1' session to remain, but it was deleted")
	}
	if _, ok := store.sessions["expired1"]; ok {
		t.Errorf("expected 'expired1' to be deleted")
	}
	if _, ok := store.sessions["expired2"]; ok {
		t.Errorf("expected 'expired2' to be deleted")
	}
}

func TestSessionStore_StartEvictionWorker(t *testing.T) {
	store := &SessionStore{
		sessions: make(map[string]SessionEntry),
		stopChan: make(chan struct{}),
	}

	// Add an already expired session
	store.sessions["expired-worker"] = SessionEntry{
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}

	// Run worker with very small interval
	go store.startEvictionWorker(10 * time.Millisecond)

	// Wait for ticker to fire and clean up
	deadline := time.Now().Add(500 * time.Millisecond)
	cleaned := false
	for time.Now().Before(deadline) {
		store.mu.RLock()
		_, exists := store.sessions["expired-worker"]
		store.mu.RUnlock()
		if !exists {
			cleaned = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !cleaned {
		t.Errorf("expected worker to evict expired session")
	}

	// Close store and ensure worker exits without deadlock
	store.Close()
}

func TestSessionStore_ConcurrentAccess(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	user := &User{email: "concurrency@example.com"}
	sessionData := &webauthn.SessionData{Challenge: "concurrent"}

	var wg sync.WaitGroup
	numWorkers := 20
	iterations := 50

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				rec := httptest.NewRecorder()
				sessionID, err := store.CreateSession(rec, sessionData, user, 10)
				if err != nil {
					t.Errorf("worker %d: CreateSession failed: %v", workerID, err)
					return
				}

				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{
					Name:  sessionCookieName,
					Value: sessionID,
				})

				entry, err := store.GetSession(req)
				if err != nil {
					t.Errorf("worker %d: GetSession failed: %v", workerID, err)
					return
				}
				if entry.User == nil || entry.User.email != "concurrency@example.com" {
					t.Errorf("worker %d: invalid user retrieved", workerID)
					return
				}

				// Occasionally delete
				if j%2 == 0 {
					delRec := httptest.NewRecorder()
					store.DeleteSession(delRec, req)
				}
			}
		}(i)
	}

	wg.Wait()
}
