package passkeys

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hesusruiz/utils/errl"
)

// superAdminMiddleware provides HTTP Basic Authentication protection for the given handler.
// It verifies the credentials against the SUPERADMIN_PASSWORD environment variable or defaults to "pepe".
func superAdminMiddleware(p *Passkeys, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		user, pass, ok := r.BasicAuth()
		thePass := os.Getenv("SUPERADMIN_PASSWORD")
		if thePass == "" {
			thePass = "pepe"
		}

		if !ok || user != "admin" || pass != thePass {
			w.Header().Set("WWW-Authenticate", `Basic realm="SuperAdmin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleCreateToken receives an email address and generates a random, secure invitation token.
// The token and its expiration date (24 hours) are stored in the database.
func (p *Passkeys) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		slog.Error("no email provided")
		http.Error(w, "no email", http.StatusBadRequest)
		return
	}

	// domain is goauth by default
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "goauth"
	}

	// function is user by default
	function := r.URL.Query().Get("function")
	if function == "" {
		function = "user"
	}

	// actions are specified in the URL as actions=act1,act2,act3
	actions := r.URL.Query().Get("actions")
	if actions == "" {
		actions = "read"
	}
	actionArray := strings.Split(actions, ",")

	pows := []OnePower{
		{
			Type:     "domain",
			Domain:   "goauth",
			Function: function,
			Action:   actionArray,
		},
	}

	// print the powers being created
	b, err := json.Marshal(pows)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error marshalling powers", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("Inviting user with powers: %s\n", string(b))

	token, err := p.InviteUserPowers(email, pows)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error creating token", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the invitation URL
	fmt.Fprintf(w, "token: %s\n", token)
}

func (p *Passkeys) InviteUserPowers(email string, pows []OnePower) (string, error) {
	// Generate a random token of 16 chars (digits 0-9, upper/lower ASCII letters, underscore)
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
	b := make([]byte, 16)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", errl.Error(err)
		}
		b[i] = charset[n.Int64()]
	}
	token := string(b)

	// Update user with token and expiry date (24 hours from now)
	tokenExpiry := time.Now().Add(24 * time.Hour)
	err := p.CreateInvitationPowers(email, pows, token, tokenExpiry)
	if err != nil {
		return "", errl.Error(err)
	}

	return token, nil
}

// InviteAdmin creates an invitation for an admin with all powers.
func (p *Passkeys) InviteAdmin(email string) (string, error) {
	// Generate a random token of 16 chars (digits 0-9, upper/lower ASCII letters, underscore)
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
	b := make([]byte, 16)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", errl.Error(err)
		}
		b[i] = charset[n.Int64()]
	}
	token := string(b)

	// Create the powers as a single element array of powers
	pows := []OnePower{
		{
			Type:     "domain",
			Domain:   "goauth",
			Function: "admin",
			Action:   []string{"*"},
		},
	}

	// Update user with token and expiry date (72 hours from now)
	tokenExpiry := time.Now().Add(72 * time.Hour)
	err := p.CreateInvitationPowers(email, pows, token, tokenExpiry)
	if err != nil {
		return "", errl.Error(err)
	}

	return token, nil
}

// CreateInvitationPowers creates an invitation with the given powers, token and expiry date.
// If no powers are provided, it creates an invitation for an admin with read access.
func (p *Passkeys) CreateInvitationPowers(email string, pows []OnePower, token string, expiry time.Time) error {

	// Create userid as a random array of 32 bytes
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return errl.Error(err)
	}

	if len(pows) == 0 {
		pows = []OnePower{
			{
				Type:     "domain",
				Domain:   "goauth",
				Function: "user",
				Action:   []string{"read"},
			},
		}
	}

	jsonPowers, err := json.Marshal(pows)
	if err != nil {
		return errl.Error(err)
	}

	fmt.Println("creating invitation expiring on", expiry.Format(time.RFC1123))

	// TODO: change the field roles to powers with a JSON type
	_, err = p.db.Exec(
		`INSERT INTO users (email, roles, userid, invitation_token, token_expiry) 
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET 
		     roles = excluded.roles,
		     invitation_token = excluded.invitation_token,
		     token_expiry = excluded.token_expiry`,
		email,
		jsonPowers,
		userID,
		token,
		expiry,
	)
	if err != nil {
		return errl.Error(err)
	}
	return nil
}
