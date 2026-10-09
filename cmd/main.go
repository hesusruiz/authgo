package main

import (
	"fmt"
	"net/http"
	"time"

	passkeys "github.com/hesusruiz/authgo"
)

func main() {

	pk, err := passkeys.NewPasskeys(passkeys.Config{
		RPDisplayName: "Admin Panel",
		RPID:          "admin.mycredential.eu",
		RPOrigins:     []string{"https://admin.mycredential.eu"},
		PathPrefix:    "/passkeys",
	})
	if err != nil {
		panic(err)
	}
	defer pk.Close()

	invitation, err := pk.InviteAdmin("jesus@alastria.io")
	if err != nil {
		panic(err)
	}
	fmt.Println("Invitation:", invitation)

	mux := http.NewServeMux()

	pk.RegisterHandlers(mux)

	// register a page at http://localhost:8090/test protected with RequirePasskey
	mux.Handle("/test", pk.RequirePasskey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := passkeys.FromContext(r.Context())
		if user == nil {
			// this shoulnd't happen
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Println("User roles:", user.Roles())
		w.Write([]byte("Hello, " + user.Email() + "!"))
	})))

	server := &http.Server{
		Addr:              ":8090",
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	fmt.Printf("Server running on http://localhost:%s\n", server.Addr)
	if err = server.ListenAndServe(); err != nil {
		panic(err)
	}
}
