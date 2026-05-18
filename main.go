package main

import (
	"embed"
	"net/http"
	"time"
)

//go:embed front/*
var embeddedFiles embed.FS

func main() {

	pk, err := NewPasskeys()
	if err != nil {
		panic(err)
	}

	// // Create a test invitation for jesus@alastria.io
	// err = pk.CreateInvitation("jesus@alastria.io", "12345", time.Now().Add(time.Hour*24))
	// if err != nil {
	// 	panic(err)
	// }

	mux := http.NewServeMux()

	// Serve the frontend
	fileSystem := getFileSystem()
	mux.Handle("/", http.FileServer(http.FS(fileSystem)))

	// Registration page and APIs
	mux.HandleFunc("/api/register/begin", pk.handleRegisterBegin)
	mux.HandleFunc("/api/register/finish", pk.handleRegisterFinish)

	// Login page and APIs
	// mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/api/login/begin", pk.handleLoginBegin)
	mux.HandleFunc("/api/login/finish", pk.handleLoginFinish)

	pk.ConfigureSuperAdminHandlers(mux)

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
