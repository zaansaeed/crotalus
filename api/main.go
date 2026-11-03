package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not specified")
	}

	// In docker-compose.yml, DATABASE_URL logs in as crotalus_api (migrations/010):
	// SELECT only, and Postgres cancels any of its queries that run over 5 seconds.
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Fatal(err)
	}
	config.MaxConns = 5 // the worker and triager share the database, so don't take many
	pool, err := pgxpool.NewWithConfig(context.Background(), config) // connection to database
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close() // runs when main is done

	// Our own router rather than http.HandleFunc's global one, which any imported
	// package could also add routes to.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler(pool))
	mux.HandleFunc("GET /flagged", flaggedHandler(pool))
	mux.HandleFunc("GET /releases/{name}/{version}", releaseHandler(pool))

	// A burst of 20 requests, then 5 a second, per client IP.
	limiter := newRateLimiter(5, 20)

	// http.ListenAndServe has no timeouts: a client that sends its request (or reads
	// the response) one byte at a time keeps a connection open for as long as it
	// likes, and enough of them use up the server (a "Slowloris" attack).
	server := &http.Server{
		Addr:              ":8080",
		Handler:           limiter.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,  // to send the request's headers
		ReadTimeout:       10 * time.Second, // to send the whole request
		WriteTimeout:      10 * time.Second, // to handle it and send the response
		IdleTimeout:       60 * time.Second, // a kept-alive connection waiting for its next request
	}
	log.Fatal(server.ListenAndServe()) // start it; blocks forever
}
