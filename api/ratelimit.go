package main

// Per-client rate limiting, so one client can't hammer the API (or the database
// behind it) and slow it down for everyone else.
//
// Each client IP gets a token bucket (golang.org/x/time/rate): it holds up to
// `burst` tokens, refills at `perSecond` tokens a second, and each request takes
// one. A client can send a quick burst, then perSecond requests a second for as
// long as it likes. An empty bucket means 429 Too Many Requests.

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// How long a client can go quiet before its bucket is forgotten (it starts full
// again next time). Without this, the map would grow by one entry per IP forever.
const forgetClientsAfter = 3 * time.Minute

type rateLimiter struct {
	mu      sync.Mutex // guards clients: every request runs in its own goroutine
	clients map[string]*client
	rate    rate.Limit // tokens added per second
	burst   int        // most tokens a bucket holds
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newRateLimiter(perSecond float64, burst int) *rateLimiter {
	limiter := &rateLimiter{
		clients: map[string]*client{},
		rate:    rate.Limit(perSecond), //how many tokens
		burst:   burst,  // token replenish per second
	}
	go limiter.forgetIdleClients() // runs in the background for as long as the API does
	return limiter
}

// Whether the client at `ip` may make a request now (and takes a token if so).
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	c, ok := rl.clients[ip]
	if !ok { // it is not ok, must be missing -> first request: a full bucket 
		c = &client{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.clients[ip] = c
	}
	c.lastSeen = time.Now()
	return c.limiter.Allow()
}

func (rl *rateLimiter) forgetIdleClients() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, c := range rl.clients {
			if time.Since(c.lastSeen) > forgetClientsAfter {
				delete(rl.clients, ip) // deleting while ranging over a map is allowed in Go
			}
		}
		rl.mu.Unlock()
	}
}

// Wraps a handler: requests over the limit get a 429, the rest go on to `next`.
func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) { // check, do we allow?
			w.Header().Set("Retry-After", "1") // seconds
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// The IP of the client that sent the request.
//
// Behind Caddy, every request arrives from Caddy's own address, so the client's is
// taken from the X-Forwarded-For header Caddy adds: its last entry is the address
// Caddy saw. A client could put anything in the header itself, but only entries
// before Caddy's, so the last one is safe to trust. And that's only true because
// nothing reaches the API except through Caddy (or localhost, which sends no header).
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Values("X-Forwarded-For"); len(forwarded) > 0 {
		entries := strings.Split(strings.Join(forwarded, ","), ",")
		return strings.TrimSpace(entries[len(entries)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr) // "1.2.3.4:5678" -> "1.2.3.4"
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
