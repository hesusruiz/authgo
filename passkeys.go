package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hesusruiz/utils/errl"
	_ "modernc.org/sqlite"
)

type Passkeys struct {
	db         *sql.DB
	waInstance *webauthn.WebAuthn
}

type User struct {
	id          []byte
	email       string
	displayName string
	credentials []webauthn.Credential
}

// WebAuthn User Interface implementation
func (u *User) WebAuthnID() []byte                         { return u.id }
func (u *User) WebAuthnName() string                       { return u.email }
func (u *User) WebAuthnDisplayName() string                { return u.email }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
func (u *User) WebAuthnIcon() string                       { return "" }

// --- 2. GLOBAL STATE (In-memory mocks for this example) ---

var (
	// In production, use a secure cookie for this!
	sessionStore = make(map[string]*webauthn.SessionData)
)

func NewPasskeys() (*Passkeys, error) {

	requireResidentKey := true

	waInstance, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         "Admin Panel",
		RPID:                  "localhost",
		RPOrigins:             []string{"http://localhost:8080"},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			UserVerification:        protocol.VerificationRequired,
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			RequireResidentKey:      &requireResidentKey,
		},
	})
	if err != nil {
		return nil, errl.Error(err)
	}

	db, err := sql.Open("sqlite", "./authn.db")
	if err != nil {
		return nil, errl.Error(err)
	}

	_, err = db.ExecContext(context.Background(), `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		userid BLOB,
		display_name TEXT,
		invitation_token TEXT,
		token_expiry DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
		
	CREATE TABLE IF NOT EXISTS credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		cred_type TEXT NOT NULL, 
		cred_id TEXT UNIQUE NOT NULL, 
		public_data BLOB NOT NULL,     
		sign_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE
	);
	`)
	if err != nil {
		log.Fatal(err)
	}

	passkeys := &Passkeys{
		db:         db,
		waInstance: waInstance,
	}

	return passkeys, nil

}

func (p *Passkeys) GetUserByEmail(email string) (*User, error) {
	var u User
	err := p.db.QueryRow("SELECT id, email FROM users WHERE email = ?", email).Scan(&u.id, &u.email)
	if err != nil {
		return nil, errl.Error(err)
	}
	return &u, nil
}

// GetUserWithCredentials retrieves a user by email along with all their registered
// WebAuthn credentials. Each credential's public_data BLOB is expected to be a
// JSON-encoded webauthn.Credential. Returns sql.ErrNoRows if the user is not found.
// Both queries run inside a single read-only transaction for a consistent snapshot.
func (p *Passkeys) GetUserWithCredentials(email string) (*User, error) {
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
	var u User
	err = tx.QueryRowContext(ctx,
		`SELECT userid, email FROM users WHERE email = ?`,
		email,
	).Scan(&u.id, &u.email)
	if err != nil {
		return nil, errl.Errorf("GetUserWithCredentials: user lookup: %w", err)
	}

	// 2. Fetch all passkey credentials credentials for this user, oldest first.
	rows, err := tx.QueryContext(ctx,
		`SELECT public_data FROM credentials WHERE user_email = ? AND cred_type = 'passkey' ORDER BY created_at ASC`,
		email,
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

func (p *Passkeys) InsertUser(email string) (*User, error) {
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return nil, err
	}

	_, err := p.db.Exec("INSERT INTO users (email, userid) VALUES (?, ?)", email, userID)
	if err != nil {
		return nil, errl.Error(err)
	}

	return &User{id: userID, email: email}, nil
}

func (p *Passkeys) UpdateUserInvitationToken(email, token string, expiry time.Time) error {
	_, err := p.db.Exec(
		"UPDATE users SET invitation_token = ?, token_expiry = ? WHERE email = ?",
		token,
		expiry,
		email,
	)
	if err != nil {
		return errl.Error(err)
	}
	return nil
}

func (p *Passkeys) GetInvitation(invitationToken string) (*User, error) {
	var u User
	var tokenExpiry sql.NullTime
	now := time.Now()

	err := p.db.QueryRow("SELECT userid, email, token_expiry FROM users WHERE invitation_token = ?", invitationToken).Scan(&u.id, &u.email, &tokenExpiry)
	// Return an error if error (includes record not found)
	if err != nil {
		if err == sql.ErrNoRows {
			err = errl.Errorf("invitation token not found")
		}
		return nil, errl.Error(err)
	}

	fmt.Println("now is", now.Format(time.RFC1123))
	fmt.Println("getting invitation expiring on", tokenExpiry.Time.Format(time.RFC1123))

	// Check for token expiration, where a null expiration time is considered an expired token
	if !tokenExpiry.Valid {
		return nil, errl.Errorf("invitation token does not have value")
	}
	if now.After(tokenExpiry.Time) {
		return nil, errl.Errorf("invitation token has expired")
	}

	// The token has been cleared, so we return the user.
	return &u, nil
}

func (p *Passkeys) DeleteInvitation(user *User) error {
	fmt.Printf("deleting invitation for user %s", user.email)
	_, err := p.db.Exec(
		"UPDATE users SET invitation_token = NULL, token_expiry = NULL WHERE email = ?",
		user.email,
	)
	if err != nil {
		return errl.Error(err)
	}
	return nil
}

func (p *Passkeys) AddCredentialToUser(user *User, credential *webauthn.Credential) error {
	blob, err := json.Marshal(credential)
	if err != nil {
		return errl.Errorf("AddCredentialToUser: marshal: %w", err)
	}

	_, err = p.db.Exec(
		"INSERT INTO credentials (user_email, cred_type, cred_id, public_data, sign_count) VALUES (?, ?, ?, ?, ?)",
		user.email,
		"passkey",
		base64.RawURLEncoding.EncodeToString(credential.ID),
		blob,
		credential.Authenticator.SignCount,
	)
	if err != nil {
		return errl.Errorf("AddCredentialToUser: insert: %w", err)
	}
	return nil
}

func (p *Passkeys) UpdateCredential(user *User, credential webauthn.Credential) error {
	blob, err := json.Marshal(credential)
	if err != nil {
		return errl.Errorf("AddCredentialToUserUpdateCredential: marshal: %w", err)
	}

	_, err = p.db.Exec(
		"UPDATE credentials SET cred_id = ?, public_data = ?, sign_count = ? WHERE user_email = ? AND cred_id = ?",
		base64.RawURLEncoding.EncodeToString(credential.ID),
		blob,
		credential.Authenticator.SignCount,
		user.email,
		base64.RawURLEncoding.EncodeToString(credential.ID),
	)
	if err != nil {
		return errl.Errorf("UpdateCredential: update: %w", err)
	}
	return nil
}

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
	sessionStore[invitationToken] = session
	fmt.Println("SessionID in BeginRegistration", resp.SessionID)

	json.NewEncoder(w).Encode(resp)
}

func (p *Passkeys) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	invitationToken := r.URL.Query().Get("t")
	session, ok := sessionStore[invitationToken]
	if !ok {
		err := errl.Errorf("token not provided or does not exist")
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
	delete(sessionStore, invitationToken)
	w.WriteHeader(http.StatusOK)
}

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

func (p *Passkeys) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// TODO: Load front/index.html (or wherever you put the login UI)
	// It should contain a "Login with Passkey" button
}

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
	sessionStore[session.Challenge] = session

	// Reply to caller
	json.NewEncoder(w).Encode(resp)
}

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

func (p *Passkeys) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	sessionId := r.URL.Query().Get("s")
	session, ok := sessionStore[sessionId]
	if !ok {
		err := errl.Errorf("token not provided or does not exist")
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

	w.WriteHeader(http.StatusOK)

}
