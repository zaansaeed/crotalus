package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not specified")
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close() // runs when main is done

	//end points
	http.HandleFunc("GET /health", healthHandler(pool)) // health endpoint
	http.HandleFunc("GET /flagged", flaggedHandler(pool))

	log.Fatal(http.ListenAndServe(":8080", nil))        // start it; blocks forever
}
