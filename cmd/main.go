package main

import (
	"net/http"
	"time"

	passkeys "github.com/hesusruiz/authgo"
)

func main() {

	pk, err := passkeys.NewPasskeys(passkeys.Config{
		RPDisplayName: "Admin Panel",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
		PathPrefix:    "/passkeys",
	})
	if err != nil {
		panic(err)
	}
	defer pk.Close()

	mux := http.NewServeMux()

	pk.RegisterHandlers(mux)

	// register a page at http://localhost:8080/test protected with RequirePasskey
	mux.Handle("/test", pk.RequirePasskey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})))

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	println("Server running on http://localhost:8080")
	if err = server.ListenAndServe(); err != nil {
		panic(err)
	}
}
