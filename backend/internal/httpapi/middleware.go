package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type requestIDContextKey struct{}

var requestIDFallbackCounter atomic.Uint64

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := newUUIDv7()
		writer.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(request.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func recoveryMiddleware(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recover() == nil {
				return
			}
			logger.Printf("panic recovered request_id=%s", requestIDFromContext(request.Context()))
			writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		}()
		next.ServeHTTP(writer, request)
	})
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
}

func newUUIDv7() string {
	var value [16]byte
	milliseconds := uint64(time.Now().UnixMilli())
	value[0] = byte(milliseconds >> 40)
	value[1] = byte(milliseconds >> 32)
	value[2] = byte(milliseconds >> 24)
	value[3] = byte(milliseconds >> 16)
	value[4] = byte(milliseconds >> 8)
	value[5] = byte(milliseconds)
	if _, err := rand.Read(value[6:]); err != nil {
		var seed [16]byte
		binary.BigEndian.PutUint64(seed[0:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(seed[8:16], requestIDFallbackCounter.Add(1))
		digest := sha256.Sum256(seed[:])
		copy(value[6:], digest[:10])
	}
	value[6] = (value[6] & 0x0f) | 0x70
	value[8] = (value[8] & 0x3f) | 0x80

	var encoded [32]byte
	hex.Encode(encoded[:], value[:])
	return string(encoded[0:8]) + "-" + string(encoded[8:12]) + "-" + string(encoded[12:16]) + "-" + string(encoded[16:20]) + "-" + string(encoded[20:32])
}

type rateBucket struct {
	attempts  int
	expiresAt time.Time
}

type ipRateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]rateBucket
	limit       int
	window      time.Duration
	maxKeys     int
	now         func() time.Time
	nextCleanup time.Time
}

func newIPRateLimiter(limit int, window time.Duration, maxKeys int, now func() time.Time) *ipRateLimiter {
	if maxKeys <= 0 {
		maxKeys = 10_000
	}
	if now == nil {
		now = time.Now
	}
	return &ipRateLimiter{
		buckets: make(map[string]rateBucket),
		limit:   limit,
		window:  window,
		maxKeys: maxKeys,
		now:     now,
	}
}

func (limiter *ipRateLimiter) allow(key string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()
	if limiter.nextCleanup.IsZero() || !now.Before(limiter.nextCleanup) {
		limiter.evictExpired(now)
		limiter.nextCleanup = now.Add(limiter.window)
	}
	bucket, exists := limiter.buckets[key]
	if exists && !now.Before(bucket.expiresAt) {
		delete(limiter.buckets, key)
		exists = false
	}
	if !exists {
		if len(limiter.buckets) >= limiter.maxKeys {
			return false
		}
		limiter.buckets[key] = rateBucket{attempts: 1, expiresAt: now.Add(limiter.window)}
		return true
	}
	if bucket.attempts >= limiter.limit {
		return false
	}
	bucket.attempts++
	limiter.buckets[key] = bucket
	return true
}

func (limiter *ipRateLimiter) evictExpired(now time.Time) {
	for key, bucket := range limiter.buckets {
		if !now.Before(bucket.expiresAt) {
			delete(limiter.buckets, key)
		}
	}
}

func (limiter *ipRateLimiter) size() int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return len(limiter.buckets)
}

func clientIP(request *http.Request, trustedProxies []netip.Prefix) string {
	peer, ok := parseRemoteIP(request.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if !ipInPrefixes(peer, trustedProxies) {
		return peer.String()
	}

	forwarded := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
	if len(forwarded) == 1 && strings.TrimSpace(forwarded[0]) == "" {
		if realIP, err := netip.ParseAddr(strings.TrimSpace(request.Header.Get("X-Real-IP"))); err == nil {
			return realIP.Unmap().String()
		}
		return peer.String()
	}
	chain := make([]netip.Addr, 0, len(forwarded))
	for _, raw := range forwarded {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return peer.String()
		}
		chain = append(chain, address.Unmap())
	}
	for index := len(chain) - 1; index >= 0; index-- {
		if !ipInPrefixes(chain[index], trustedProxies) {
			return chain[index].String()
		}
	}
	return chain[0].String()
}

func parseRemoteIP(remoteAddress string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	address, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func ipInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
