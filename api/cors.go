package main

import "net/http"

// allowCrossOrigin lets JavaScript on any other website (e.g. a GitHub Page) read the
// responses. "*" is safe here: the data is
// public, the API is read-only, and there are no cookies or logins to misuse.
func allowCrossOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}
