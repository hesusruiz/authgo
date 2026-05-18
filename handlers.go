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
	"os"
	"path/filepath"
	"runtime"

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

	// Serve the frontend
	fileSystem := getFileSystem()
	mux.Handle("/", http.FileServer(http.FS(fileSystem)))

	// Registration page and APIs
	mux.HandleFunc("/api/register/begin", p.handleRegisterBegin)
	mux.HandleFunc("/api/register/finish", p.handleRegisterFinish)

	// Login page and APIs
	mux.HandleFunc("/api/login/begin", p.handleLoginBegin)
	mux.HandleFunc("/api/login/finish", p.handleLoginFinish)

}

// handleRegisterBegin initiates the WebAuthn registration process for a user.
// It verifies the provided invitation token and returns the credential creation options.
func (p *Passkeys) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {

	// The user must provide the invitation invitationToken that she received via email or any other mechanism
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

	type response struct {
		CredentialOptions *protocol.CredentialCreation `json:"credentialOptions"`
		SessionID         string                       `json:"sessionid"`
	}

	resp := response{
		CredentialOptions: options,
		SessionID:         session.Challenge,
	}

	// Store session temporarily to verify the next request
	err = p.sessionStore.SaveSession(w, session, 0)
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
	fmt.Println("challenge in FinishingRegistration", session.Challenge)

	// Get user associated with the invitation token
	user, err := p.GetInvitation(invitationToken)
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing registration", "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	credential, err := p.waInstance.FinishRegistration(user, *session, r)
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
	w.WriteHeader(http.StatusOK)
}

// getFileSystem returns an fs.FS to serve frontend files. In development mode
// it serves directly from the 'front' directory to allow live reloads. In production,
// it uses the embedded filesystem.
func getFileSystem() fs.FS {
	// Set to false when deploying to production
	useLive := true

	// Get the path to this specific .go file
	_, thisFilePath, _, ok := runtime.Caller(0)

	if useLive && ok {
		// The frontend files should be in the 'front' subdirectory
		thisFileDir := filepath.Dir(thisFilePath)
		// Join with the frontend folder
		frontendPath := filepath.Join(thisFileDir, "front")

		println("Development mode: Serving from", frontendPath)
		return os.DirFS(frontendPath)
	}

	// Production: Use embedded files
	// We use fs.Sub to strip the "front" prefix from the embed paths
	f, _ := fs.Sub(embeddedFiles, "front")
	return f
}

// handleLoginPage serves the initial HTML page containing the login and registration UI.
func (p *Passkeys) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// TODO: Load front/index.html (or wherever you put the login UI)
	// It should contain a "Login with Passkey" button
}

// handleLoginBegin initiates the WebAuthn discoverable login (passkey) flow,
// returning the credential assertion options to the client.
func (p *Passkeys) handleLoginBegin(w http.ResponseWriter, r *http.Request) {

	// Get the challenge
	assertion, session, err := p.waInstance.BeginDiscoverableLogin()
	if err != nil {
		err = errl.Error(err)
		slog.Error("finishing login", "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	type response struct {
		CredentialAssertion *protocol.CredentialAssertion `json:"credentialAssertion"`
		SessionID           string                        `json:"sessionid"`
	}

	resp := response{
		CredentialAssertion: assertion,
		SessionID:           session.Challenge,
	}

	// Store session temporarily to verify the next request
	err = p.sessionStore.SaveSession(w, session, 0)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error saving session", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Reply to caller
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
	fmt.Println("challenge in FinishingLogin", session.Challenge)

	validatedUser, validatedCredential, err := p.waInstance.FinishPasskeyLogin(p.loadUserFromPasskey, *session, r)
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
	// metadata for this credential has been updated. No type assertion is required here since the LoadUser function
	// returns the concrete implementation, you may have to adjust this if you return the abstract implementation
	// instead.
	for i, credential := range user.credentials {
		if bytes.Equal(validatedCredential.ID, credential.ID) {
			user.credentials[i] = *validatedCredential

			// Crude / Abstract example of saving the user with their updated credentials. This is critical for
			// proper future validations.
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

	p.sessionStore.DeleteSession(w, r)
	w.WriteHeader(http.StatusOK)

}
