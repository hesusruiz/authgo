// Package passkeys provides a set of structures and methods
// for managing WebAuthn passkey authentication, user registration, and SQLite-backed
// storage within an application.
package passkeys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hesusruiz/utils/errl"
	_ "modernc.org/sqlite"
)

// Config defines the configuration parameters for the Passkeys manager.
type Config struct {
	RPDisplayName           string   // Relying Party Display Name
	RPID                    string   // Relying Party ID (domain name)
	RPOrigins               []string // Allowed Relying Party origins
	PathPrefix              string   // URL prefix group for the endpoints (defaults to "/passkeys")
	DB                      *sql.DB  // Pre-configured database connection (optional)
	DBDriver                string   // Driver name, e.g., "sqlite" (optional)
	DBSourceName            string   // Connection string or file path (optional)
	UnauthenticatedRedirect string   // Path to redirect unauthenticated users (optional)
	SkipSchemaMigration     bool     // Set to true to disable automatic database table creation
	HomePage                string   // Default redirect URL upon successful login/registration if 'next' is empty (defaults to "/")
}

// Passkeys is the primary manager for WebAuthn authentication, encapsulating the database connection,
// the WebAuthn instance, and the session storage mechanism.
type Passkeys struct {
	db           *sql.DB
	waInstance   *webauthn.WebAuthn
	sessionStore *SessionStore
	cfg          Config
	isDBOwned    bool
}

// User represents an authenticated entity within the system. It implements the
// webauthn.User interface required for credential creation and validation.
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

// ID returns the user's ID.
func (u *User) ID() []byte { return u.id }

// Email returns the user's email address.
func (u *User) Email() string { return u.email }

// DisplayName returns the user's display name.
func (u *User) DisplayName() string { return u.displayName }

type contextKey string

const userCtxKey contextKey = "user"

// FromContext retrieves the authenticated User from the request context.
func FromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userCtxKey).(*User)
	return u
}

// NewPasskeys initializes a new Passkeys manager using the provided configuration.
// It sets up the WebAuthn parameters, establishes or reuses the database connection,
// performs schema initialization if required, and returns the configured manager.
func NewPasskeys(cfg Config) (*Passkeys, error) {

	// Apply default values if not provided
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "Admin Panel"
	}
	if cfg.RPID == "" {
		cfg.RPID = "localhost"
	}
	if len(cfg.RPOrigins) == 0 {
		cfg.RPOrigins = []string{"http://localhost:8080"}
	}
	if cfg.HomePage == "" {
		cfg.HomePage = "/"
	}

	requireResidentKey := true

	waInstance, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         cfg.RPDisplayName,
		RPID:                  cfg.RPID,
		RPOrigins:             cfg.RPOrigins,
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

	var db *sql.DB
	var isDBOwned bool

	if cfg.DB != nil {
		db = cfg.DB
	} else {
		driver := cfg.DBDriver
		if driver == "" {
			driver = "sqlite"
		}
		source := cfg.DBSourceName
		if source == "" {
			source = "./data/webauthn.db"
		}
		db, err = sql.Open(driver, source)
		if err != nil {
			return nil, errl.Error(err)
		}
		isDBOwned = true
	}

	if !cfg.SkipSchemaMigration {
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
			if isDBOwned {
				db.Close()
			}
			return nil, errl.Errorf("schema migration failed: %w", err)
		}
	}

	passkeys := &Passkeys{
		db:           db,
		waInstance:   waInstance,
		sessionStore: NewSessionStore(),
		cfg:          cfg,
		isDBOwned:    isDBOwned,
	}

	return passkeys, nil

}

// Close gracefully releases any active database connection opened by the manager
// and terminates the background session eviction worker.
func (p *Passkeys) Close() error {
	if p.sessionStore != nil {
		p.sessionStore.Close()
	}
	if p.isDBOwned && p.db != nil {
		return p.db.Close()
	}
	return nil
}

// GetUserByEmail looks up a user in the SQLite database by their email address.
// It returns the User structure or an error if the user is not found.
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

// InsertUser generates a unique 32-byte ID for a new user and inserts their
// basic record into the database, returning the initialized User structure.
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

// UpdateUserInvitationToken sets a new invitation token and its expiration
// timestamp for a specific user's email address.
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

// GetInvitation attempts to locate a user by a valid, unexpired invitation token.
// It returns an error if the token does not exist, is invalid, or has expired.
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

// DeleteInvitation removes the invitation token and its expiration from the
// specified user's record, preventing reuse of the token.
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

// AddCredentialToUser serializes and stores a new WebAuthn credential into the
// database, associating it with the provided user's email.
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

// UpdateCredential updates the stored data and signature count for an existing
// WebAuthn credential belonging to the specified user.
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
