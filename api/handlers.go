package main //part of main package

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"strconv"
	"encoding/json"
)

// w the response, r is the request the user sent
func healthHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { //equiv of lambda function, since server requires function of this type.
		err := pool.Ping(r.Context())
		if err != nil {
			log.Printf("health: database ping failed: %v", err)
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //byte slice->strings can be dynamic in size 1..n bytes. so an array of bytes. write only understands bytes
	}
}

func flaggedHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. read ?limit=
		limit := 50                                  // default
		if s := r.URL.Query().Get("limit"); s != "" { //parse the URL into a dict .Query()
			n, err := strconv.Atoi(s)                // "20" → 20; "abc" → error
			if err != nil || n < 1 || n > 500 {
				http.Error(w, "limit must be 1-500", http.StatusBadRequest)
				return
			}
			limit = n
		}
		
		releases, err := flaggedReleases(r.Context(), pool, limit)
		if err != nil {
			log.Printf("flagged: query failed: %v", err)   
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(releases)
	}
}