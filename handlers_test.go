package passkeys

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequirePasskey(t *testing.T) {
	// Initialize a real Passkeys manager with in-memory SQLite DB
	pk, err := NewPasskeys(Config{
		DBSourceName: ":memory:",
		PathPrefix:   "/passkeys",
	})
	if err != nil {
		t.Fatalf("failed to initialize Passkeys: %v", err)
	}
	defer pk.Close()

	// Register a dummy user
	user, err := pk.InsertUser("test@example.com")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	// 1. Test default redirect to path prefix (should append safe next parameter)
	req := httptest.NewRequest("GET", "/protected", nil)
	rr := httptest.NewRecorder()

	handler := pk.RequirePasskey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/passkeys/?next=%2Fprotected" {
		t.Errorf("expected redirect to /passkeys/?next=%%2Fprotected, got %s", loc)
	}

	// 2. Test custom redirect path (should append safe next parameter)
	pkCustom, err := NewPasskeys(Config{
		DBSourceName:            ":memory:",
		PathPrefix:              "/passkeys",
		UnauthenticatedRedirect: "/custom-login",
	})
	if err != nil {
		t.Fatalf("failed to initialize custom Passkeys: %v", err)
	}
	defer pkCustom.Close()

	rrCustom := httptest.NewRecorder()
	handlerCustom := pkCustom.RequirePasskey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handlerCustom.ServeHTTP(rrCustom, req)
	if loc := rrCustom.Header().Get("Location"); loc != "/custom-login?next=%2Fprotected" {
		t.Errorf("expected redirect to /custom-login?next=%%2Fprotected, got %s", loc)
	}

	// 2b. Test open redirect prevention (unsafe request URIs should not be appended)
	unsafeRequests := []struct {
		label string
		path  string
	}{
		{label: "//evil.com/payload", path: "//evil.com/payload"},
		{label: "/\\evil.com", path: "/\\evil.com"},
		{label: "/%5Cevil.com", path: "/%5Cevil.com"},
		{label: "/%5cevil.com", path: "/%5cevil.com"},
		{label: "/%255Cevil.com", path: "/%255Cevil.com"},
		{label: "http://evil.com/payload", path: "http://evil.com/payload"},
		{label: "javascript:alert(1)", path: "javascript:alert(1)"},
		{label: "/javascript:alert(1)", path: "/javascript:alert(1)"},
	}

	for _, tc := range unsafeRequests {
		reqUnsafe := httptest.NewRequest("GET", "/", nil)
		reqUnsafe.URL.Opaque = ""
		reqUnsafe.URL.Path = tc.path

		rrUnsafe := httptest.NewRecorder()
		handler.ServeHTTP(rrUnsafe, reqUnsafe)

		if rrUnsafe.Code != http.StatusFound {
			t.Errorf("expected status 302 for unsafe redirect, got %d", rrUnsafe.Code)
		}
		loc := rrUnsafe.Header().Get("Location")
		if strings.Contains(loc, "next=") {
			t.Errorf("expected no next parameter appended for unsafe URI %q, got %s", tc.label, loc)
		}
	}

	// 3. Test with active session (should allow request to proceed and inject context)
	rrSession := httptest.NewRecorder()

	// Create a dummy session with the registered user's credentials
	_, err = pk.sessionStore.CreateSession(rrSession, nil, user, 3600)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Copy cookie to request
	reqWithCookie := httptest.NewRequest("GET", "/protected", nil)
	cookies := rrSession.Result().Cookies()
	for _, cookie := range cookies {
		reqWithCookie.AddCookie(cookie)
	}

	rr2 := httptest.NewRecorder()

	// A special test handler that asserts the presence and details of the injected user from context
	assertingHandler := pk.RequirePasskey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxUser := FromContext(r.Context())
		if ctxUser == nil {
			t.Error("expected non-nil user in request context")
			http.Error(w, "missing user in context", http.StatusInternalServerError)
			return
		}
		if ctxUser.Email() != "test@example.com" {
			t.Errorf("expected user email 'test@example.com', got %q", ctxUser.Email())
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	assertingHandler.ServeHTTP(rr2, reqWithCookie)

	if rr2.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr2.Code)
	}
	if body := rr2.Body.String(); body != "ok" {
		t.Errorf("expected body 'ok', got %q", body)
	}
}

func TestRequirePasskey_ContentNegotiation(t *testing.T) {
	pk, err := NewPasskeys(Config{
		DBSourceName: ":memory:",
		PathPrefix:   "/passkeys",
	})
	if err != nil {
		t.Fatalf("failed to initialize Passkeys: %v", err)
	}
	defer pk.Close()

	handler := pk.RequirePasskey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	// 1. Test unauthenticated request with JSON Accept header -> returns 401 JSON
	reqAPI := httptest.NewRequest("GET", "/protected", nil)
	reqAPI.Header.Set("Accept", "application/json")
	rrAPI := httptest.NewRecorder()

	handler.ServeHTTP(rrAPI, reqAPI)

	if rrAPI.Code != http.StatusUnauthorized {
		t.Errorf("expected API status 401, got %d", rrAPI.Code)
	}
	if contentType := rrAPI.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}
	if body := rrAPI.Body.String(); !strings.Contains(body, `"error":"unauthorized"`) {
		t.Errorf("expected body to contain error json, got %q", body)
	}

	// 2. Test unauthenticated request with API path -> returns 401 JSON
	reqAPIPath := httptest.NewRequest("GET", "/api/protected", nil)
	rrAPIPath := httptest.NewRecorder()

	handler.ServeHTTP(rrAPIPath, reqAPIPath)

	if rrAPIPath.Code != http.StatusUnauthorized {
		t.Errorf("expected API path status 401, got %d", rrAPIPath.Code)
	}

	// 3. Test unauthenticated page request -> returns 302 redirect
	reqPage := httptest.NewRequest("GET", "/protected", nil)
	rrPage := httptest.NewRecorder()

	handler.ServeHTTP(rrPage, reqPage)

	if rrPage.Code != http.StatusFound {
		t.Errorf("expected Page status 302, got %d", rrPage.Code)
	}
}
