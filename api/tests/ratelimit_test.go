package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  []string // X-Forwarded-For header lines
		want       string
	}{
		{"no proxy", "203.0.113.7:51234", nil, "203.0.113.7"},
		{"behind Caddy", "172.18.0.5:40000", []string{"203.0.113.7"}, "203.0.113.7"},
		// A client can fake the start of the header, but Caddy's entry comes last.
		{"faked by the client", "172.18.0.5:40000", []string{"1.1.1.1, 203.0.113.7"}, "203.0.113.7"},
		{"several header lines", "172.18.0.5:40000", []string{"1.1.1.1", "203.0.113.7"}, "203.0.113.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/flagged", nil)
			r.RemoteAddr = tt.remoteAddr
			for _, value := range tt.forwarded {
				r.Header.Add("X-Forwarded-For", value)
			}
			if got := clientIP(r); got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimiterAllowsABurstThenRefuses(t *testing.T) {
	limiter := newRateLimiter(1, 3) // 3 at once, then 1 a second
	for i := range 3 {
		if !limiter.allow("203.0.113.7") {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}
	if limiter.allow("203.0.113.7") {
		t.Error("4th request right away was allowed, want refused")
	}
	if !limiter.allow("198.51.100.9") {
		t.Error("another client was refused: each IP should have its own bucket")
	}
}

func TestMiddlewareSends429OverTheLimit(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := newRateLimiter(1, 1).middleware(ok)

	statuses := []int{}
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/flagged", nil))
		statuses = append(statuses, w.Code)
	}
	if statuses[0] != http.StatusOK || statuses[1] != http.StatusTooManyRequests {
		t.Errorf("statuses = %v, want [200 429]", statuses)
	}
}
