package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/starloader/backend/internal/security"
)

// BearerVerifier verifies a session token presented in an Authorization header.
type BearerVerifier interface {
	Verify(string) (security.SessionClaims, error)
}

type sessionClaimsContextKey struct{}

type DPoPReplayStore interface {
	ConsumeDPoP(context.Context, [32]byte, time.Time) (bool, error)
}

type SessionAuthConfig struct {
	PublicBaseURL string
	Replays       DPoPReplayStore
	Now           func() time.Time
}

func ValidPublicBaseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return u.Scheme == "http" && err == nil && ip.IsLoopback()
}

// RequireSession admits only requests bearing a verified session token.
func RequireSession(verifier BearerVerifier, next http.Handler, options ...SessionAuthConfig) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 {
			writeInvalidSessionToken(writer, request)
			return
		}
		fields := strings.Fields(values[0])
		if len(fields) != 2 || fields[0] != "DPoP" || verifier == nil {
			writeInvalidSessionToken(writer, request)
			return
		}
		claims, err := verifier.Verify(fields[1])
		if err != nil {
			writeInvalidSessionToken(writer, request)
			return
		}
		proofs := request.Header.Values("DPoP")
		if len(options) != 1 || len(proofs) != 1 || claims.ProofBound == nil || options[0].Replays == nil || !ValidPublicBaseURL(options[0].PublicBaseURL) {
			writeInvalidSessionToken(writer, request)
			return
		}
		now := time.Now().UTC()
		if options[0].Now != nil {
			now = options[0].Now().UTC()
		}
		if !claims.ExpiresAt.After(now) {
			writeInvalidSessionToken(writer, request)
			return
		}
		proof, err := security.VerifyDPoP(security.DPoPInput{Proof: proofs[0], AccessToken: fields[1], Method: request.Method,
			URI: strings.TrimRight(options[0].PublicBaseURL, "/") + request.URL.EscapedPath(), Token: claims, Now: now})
		if err != nil {
			writeInvalidSessionToken(writer, request)
			return
		}
		consumed, err := options[0].Replays.ConsumeDPoP(request.Context(), proof.JTIDigest, claims.ExpiresAt)
		if err != nil || !consumed {
			writeInvalidSessionToken(writer, request)
			return
		}
		ctx := context.WithValue(request.Context(), sessionClaimsContextKey{}, claims)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// SessionClaimsFromContext returns the verified session claims, when present.
func SessionClaimsFromContext(ctx context.Context) (security.SessionClaims, bool) {
	claims, ok := ctx.Value(sessionClaimsContextKey{}).(security.SessionClaims)
	return claims, ok
}

func writeInvalidSessionToken(writer http.ResponseWriter, request *http.Request) {
	writeError(writer, request, http.StatusUnauthorized, "INVALID_SESSION_TOKEN", "invalid session token")
}
