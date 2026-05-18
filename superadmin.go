package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/hesusruiz/utils/errl"
)

func (p *Passkeys) ConfigureSuperAdminHandlers(mux *http.ServeMux) {
	// SuperAdmin: mTLS + Basic Auth protected
	mux.Handle("/api/superadmin/create-token", superAdminMiddleware(p, http.HandlerFunc(p.handleCreateToken)))
}

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

// handleCreateToken recives an email and generates a token for it, returning the url
func (p *Passkeys) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		slog.Error("no email provided")
		http.Error(w, "no email", http.StatusBadRequest)
		return
	}

	// Generate a random token as a string of 10 ASCII chars and numbers
	b := make([]byte, 10)
	_, err := rand.Read(b)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error creating token", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token := base64.URLEncoding.EncodeToString(b)

	// Update user with token and expiry date (24 hours from now)
	tokenExpiry := time.Now().Add(24 * time.Hour)
	err = p.CreateInvitation(email, token, tokenExpiry)
	if err != nil {
		err = errl.Error(err)
		slog.Error("error getting invitation", "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Return the invitation URL
	fmt.Fprintf(w, "token: %s\n", token)
}

func (p *Passkeys) CreateInvitation(email string, token string, expiry time.Time) error {

	// Create userid as a random array of 32 bytes
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return errl.Error(err)
	}

	fmt.Println("creating invitation expiring on", expiry.Format(time.RFC1123))

	_, err := p.db.Exec(
		`INSERT INTO users (email, userid, invitation_token, token_expiry) 
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET 
		     invitation_token = excluded.invitation_token,
		     token_expiry = excluded.token_expiry`,
		email,
		userID,
		token,
		expiry,
	)
	if err != nil {
		return errl.Error(err)
	}
	return nil
}
