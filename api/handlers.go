package main //part of main package

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
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
