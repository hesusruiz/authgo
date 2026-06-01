package passkeys

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hesusruiz/utils/errl"
)

//go:embed front/*
var embeddedFiles embed.FS

// RegisterHandlers binds the core frontend, registration, and login HTTP endpoints
// to the provided ServeMux instance.
func (p *Passkeys) RegisterHandlers(mux *http.ServeMux) {
	// If no mux is provided, use the default ServeMux
	if mux == nil {
		mux = http.DefaultServeMux
	}

	prefix := p.cfg.PathPrefix
	if prefix == "" {
		prefix = "/passkeys"
	}

	// Clean and normalize the path prefix: ensure it starts with / and ends without a trailing slash
	prefix = "/" + strings.Trim(prefix, "/")
	if prefix == "/" {
		prefix = ""
	}

	// Serve the frontend
	fileSystem := getFileSystem()
	if prefix != "" {
		mux.Handle(prefix+"/", http.StripPrefix(prefix, http.FileServer(http.FS(fileSystem))))
	} else {
		mux.Handle("/", http.FileServer(http.FS(fileSystem)))
	}

	// Registration page and APIs
	mux.HandleFunc(prefix+"/api/register/begin", p.handleRegisterBegin)
	mux.HandleFunc(prefix+"/api/register/finish", p.handleRegisterFinish)

	// Login page and APIs
	mux.HandleFunc(prefix+"/api/login/begin", p.handleLoginBegin)
	mux.HandleFunc(prefix+"/api/login/finish", p.handleLoginFinish)

	// Logoff APIs
	mux.HandleFunc(prefix+"/api/logout", p.handleLogout)

	// SuperAdmin: mTLS + Basic Auth protected
	mux.Handle(prefix+"/api/superadmin/create-token", superAdminMiddleware(p, http.HandlerFunc(p.handleCreateToken)))

}

// handleRegisterBegin initiates the WebAuthn registration process for a user.
// It verifies the provided invitation token and returns the credential creation options.
func (p *Passkeys) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	// Check if user is already authenticated
	if session, err := p.sessionStore.GetSession(r); err == nil && session.User != nil {
		nextParam := r.URL.Query().Get("next")
		redirectURL := p.cfg.HomePage
		if nextParam != "" && isSafeLocalRedirect(nextParam) {
			redirectURL = nextParam
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"authenticated": true,
			"redirectUrl":   redirectURL,
		})
		return
	}

	// The user must provide the invitation Token that she received via email or any other mechanism
	invitationToken := r.URL.Query().Get("t")
	if invitationToken == "" {
		slog.Error("no token provided")
		http.Error(w, "no token", http.StatusBadRequest)
		return
	}

	// Get user from DB via invitation token
	user, err := p.GetInvitation(invitationToken)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error getting invitation", "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Accept only ES256 or RS256
	registrationParameters := webauthn.WithCredentialParameters([]protocol.CredentialParameter{
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}, // ES256
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256}, // RS256
	})

	options, session, err := p.waInstance.BeginRegistration(user, registrationParameters)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error beginning registration", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type registerBeginResponse struct {
		CredentialOptions *protocol.CredentialCreation `json:"credentialOptions"`
		SessionID         string                       `json:"sessionid"`
	}

	resp := registerBeginResponse{
		CredentialOptions: options,
		SessionID:         session.Challenge,
	}

	// Store session temporarily to verify the next request
	_, err = p.sessionStore.CreateSession(w, session, nil, 0)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error saving session", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("SessionID in BeginRegistration", resp.SessionID)

	json.NewEncoder(w).Encode(resp)
}

// handleRegisterFinish completes the WebAuthn registration. It validates the client's
// attestation response, saves the new credential, and consumes the invitation token.
func (p *Passkeys) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	invitationToken := r.URL.Query().Get("t")
	session, err := p.sessionStore.GetSession(r)
	if err != nil {
		err = errl.Errorf("session not found: %v", err)
		slog.Error("finishing registration", "error", err.Error())
		http.Error(w, "session not found", http.StatusBadRequest)
		return
	}

	fmt.Println("sessionId in FinishingRegistration", invitationToken)
	fmt.Println("challenge in FinishingRegistration", session.WASession.Challenge)

	// Get user associated with the invitation token
	user, err := p.GetInvitation(invitationToken)
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing registration", "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	credential, err := p.waInstance.FinishRegistration(user, *session.WASession, r)
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing registration", "error", err)
		http.Error(w, err.Error(), 400)
		return
	}

	// Delete the invitation
	err = p.DeleteInvitation(user)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error deleting the invitation", "email", user.email, "webauthn_id", user.WebAuthnID(), "error", err)
	}

	// Save the credential to SQLite
	err = p.AddCredentialToUser(user, credential)
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing registration", "error", err)
		http.Error(w, "Error saving credential: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Successfully registered key for %s\n", user.email)
	p.sessionStore.DeleteSession(w, r)

	_, err = p.sessionStore.CreateSession(w, nil, user, 3600)
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing registration", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Tell the caller to where to redirect
	nextParam := r.URL.Query().Get("next")
	redirectURL := p.cfg.HomePage
	if nextParam != "" && isSafeLocalRedirect(nextParam) {
		redirectURL = nextParam
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"success": true,
		"message": "Registration successful",
		"data": map[string]string{
			"redirectUrl": redirectURL,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// getFileSystem returns an fs.FS to serve frontend files. In development mode
// it serves directly from the 'front' directory to allow live reloads. In production,
// it uses the embedded filesystem.
func getFileSystem() fs.FS {

	// Get the path to this specific .go file, and serve from the '/front' subdirectory if it exists
	if _, thisFilePath, _, ok := runtime.Caller(0); ok {

		// The frontend files should be in the 'front' subdirectory
		thisFileDir := filepath.Dir(thisFilePath)
		frontendPath := filepath.Join(thisFileDir, "front")

		if _, err := os.Stat(frontendPath); err == nil {
			println("Development mode: Serving from", frontendPath)
			return os.DirFS(frontendPath)
		}
	}

	// Otherwise, serve from the embedded filesystem
	// We use fs.Sub to strip the "front" prefix from the embed paths
	f, _ := fs.Sub(embeddedFiles, "front")
	return f
}

// handleLoginBegin initiates the WebAuthn discoverable login (passkey) flow,
// returning the credential assertion options to the client.
func (p *Passkeys) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	// Check if user is already authenticated
	if session, err := p.sessionStore.GetSession(r); err == nil && session.User != nil {
		nextParam := r.URL.Query().Get("next")
		redirectURL := p.cfg.HomePage
		if nextParam != "" && isSafeLocalRedirect(nextParam) {
			redirectURL = nextParam
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"authenticated": true,
			"redirectUrl":   redirectURL,
		})
		return
	}

	// Get the challenge
	assertion, session, err := p.waInstance.BeginDiscoverableLogin()
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing login", "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	type loginBeginResponse struct {
		CredentialAssertion *protocol.CredentialAssertion `json:"credentialAssertion"`
		SessionID           string                        `json:"sessionid"`
	}

	resp := loginBeginResponse{
		CredentialAssertion: assertion,
		SessionID:           session.Challenge,
	}

	// Store session temporarily to verify in the handleLoginFinish request
	_, err = p.sessionStore.CreateSession(w, session, nil, 0)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error saving session", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Reply to caller
	json.NewEncoder(w).Encode(resp)
}

// handleLoginFinish finalizes the WebAuthn login flow by validating the client's
// assertion response against the user's stored credentials, updating the credential
// sign count upon success.
func (p *Passkeys) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	sessionId := r.URL.Query().Get("s")
	session, err := p.sessionStore.GetSession(r)
	if err != nil {
		err = errl.Errorf("session not found: %v", err)
		slog.Error("finishing login", "error", err.Error())
		http.Error(w, "session not found", http.StatusBadRequest)
		return
	}

	fmt.Println("sessionId in FinishingLogin", sessionId)
	fmt.Println("challenge in FinishingLogin", session.WASession.Challenge)

	validatedUser, validatedCredential, err := p.waInstance.FinishPasskeyLogin(p.loadUserFromPasskey, *session.WASession, r)
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing login", "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// This type assertion is necessary to perform the necessary updates.
	user, ok := validatedUser.(*User)
	if !ok {
		err = errl.Error(err)
		slog.Error("finishing login", "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var found bool

	// Modify the matching credential in the user struct which is critical for proper future validations as the
	// metadata for this credential has been updated.
	for i, credential := range user.credentials {
		if bytes.Equal(validatedCredential.ID, credential.ID) {

			// Update the credential both in-memory and in the database.
			user.credentials[i] = *validatedCredential

			if err = p.UpdateCredential(user, user.credentials[i]); err != nil {
				err = errl.Error(err)
				slog.Error("finishing login", "error", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			found = true

			break
		}
	}

	// Should error if we can't update the credentials for the user.
	if !found {
		err = errl.Error(err)
		slog.Error("credential not found for update", "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Delete current short-term session and create a new one for the whole Login process.
	// So far we have only done /begin and /finish.
	p.sessionStore.DeleteSession(w, r)

	_, err = p.sessionStore.CreateSession(w, nil, user, 3600)
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing login", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	nextParam := r.URL.Query().Get("next")
	redirectURL := p.cfg.HomePage
	if nextParam != "" && isSafeLocalRedirect(nextParam) {
		redirectURL = nextParam
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"success": true,
		"message": "Login successful",
		"data": map[string]string{
			"redirectUrl": redirectURL,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// loadUserFromPasskey is an internal callback used by the WebAuthn library
// during login to locate the corresponding user from their WebAuthn user handle.
func (p *Passkeys) loadUserFromPasskey(rawID []byte, userHandle []byte) (user webauthn.User, err error) {

	var u User

	ctx := context.Background()

	// Open a read-only transaction so both queries see the same DB snapshot.
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errl.Errorf("GetUserWithCredentials: begin tx: %w", err)
	}
	// A read-only transaction only needs a rollback (commit would work too, but
	// rollback is the safe default when we might return early on error).
	defer tx.Rollback() //nolint:errcheck

	// 1. Fetch the user row.
	err = tx.QueryRowContext(ctx,
		`SELECT userid, email FROM users WHERE userid = ?`,
		userHandle,
	).Scan(&u.id, &u.email)
	if err != nil {
		return nil, errl.Errorf("GetUserWithCredentials: user lookup: %w", err)
	}

	// 2. Fetch all passkey credentials credentials for this user, oldest first.
	rows, err := tx.QueryContext(ctx,
		`SELECT public_data FROM credentials WHERE user_email = ? AND cred_type = 'passkey' ORDER BY created_at ASC`,
		u.email,
	)
	if err != nil {
		return nil, errl.Errorf("GetUserWithCredentials: credentials query: %w", err)
	}
	defer rows.Close()

	// 3. Deserialize each credential from its JSON blob.
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, errl.Errorf("GetUserWithCredentials: scan: %w", err)
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(blob, &cred); err != nil {
			return nil, errl.Errorf("GetUserWithCredentials: unmarshal: %w", err)
		}
		u.credentials = append(u.credentials, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, errl.Errorf("GetUserWithCredentials: rows: %w", err)
	}

	return &u, nil

}

// handleLogout logs the user out by deleting the session cookie and redirect to Login
func (p *Passkeys) handleLogout(w http.ResponseWriter, r *http.Request) {
	p.sessionStore.DeleteSession(w, r)
	p.redirectToLogin(w, r)
}

// RequirePasskey checks for the existence of a valid login session and redirects unauthenticated
// requests to the configured login path or custom redirect URL, or returns 401 Unauthorized for API requests.
// If authenticated, it retrieves the user details from the session (without hitting the database)
// and injects the User struct into the request context.
func (p *Passkeys) RequirePasskey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := p.sessionStore.GetSession(r)
		if err != nil || session.User == nil {
			if isAPIRequest(r) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
				return
			}
			p.redirectToLogin(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), userCtxKey, session.User)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *Passkeys) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	redirectPath := p.cfg.UnauthenticatedRedirect
	if redirectPath == "" {
		prefix := p.cfg.PathPrefix
		if prefix == "" {
			prefix = "/passkeys"
		}
		prefix = "/" + strings.Trim(prefix, "/")
		redirectPath = prefix + "/"
	}

	reqURI := r.URL.RequestURI()
	// Only append 'next' if it's a safe local redirect target and not already the redirectPath itself
	if reqURI != "" && reqURI != "/" && !strings.HasPrefix(reqURI, redirectPath) {
		if isSafeLocalRedirect(reqURI) {
			if strings.Contains(redirectPath, "?") {
				redirectPath += "&next=" + url.QueryEscape(reqURI)
			} else {
				redirectPath += "?next=" + url.QueryEscape(reqURI)
			}
		}
	}

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

// isSafeLocalRedirect checks if a URL path is safe for redirection.
// It must start with a single '/' and not with '//', '/\' or '\\'.
// Colons ':' are also restricted to prevent protocol schemes (like javascript: or http:),
// unless they appear after a '?' or '#' (within query params/hash).
func isSafeLocalRedirect(path string) bool {
	if path == "" {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		return false
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return false
	}
	// Unescape the path recursively (up to 5 levels to handle nested URL encoding)
	// and reject if any level contains a backslash.
	unescaped := path
	for range 5 {
		if strings.Contains(unescaped, "\\") {
			return false
		}
		nextUnescaped, err := url.PathUnescape(unescaped)
		if err != nil || nextUnescaped == unescaped {
			break
		}
		unescaped = nextUnescaped
	}
	if strings.Contains(unescaped, "\\") {
		return false
	}
	if strings.Contains(path, ":") {
		posCol := strings.Index(path, ":")
		posQM := strings.Index(path, "?")
		posHash := strings.Index(path, "#")
		if (posQM == -1 || posCol < posQM) && (posHash == -1 || posCol < posHash) {
			return false
		}
	}
	return true
}

func isAPIRequest(r *http.Request) bool {
	if strings.Contains(r.URL.Path, "/api/") {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}
	return false
}
