package main

import (
	"net/http"
	"time"

	passkeys "github.com/hesusruiz/authgo"
)

func main() {

	pk, err := passkeys.NewPasskeys()
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	pk.RegisterHandlers(mux)

	pk.RegisterSuperAdminHandlers(mux)

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
