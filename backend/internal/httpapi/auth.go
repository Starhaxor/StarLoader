package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/starloader/backend/internal/security"
)

// BearerVerifier verifies a session token presented in an Authorization header.
type BearerVerifier interface {
	Verify(string) (security.SessionClaims, error)
}

type sessionClaimsContextKey struct{}

// RequireSession admits only requests bearing a verified session token.
func RequireSession(verifier BearerVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 {
			writeInvalidSessionToken(writer, request)
			return
		}
		fields := strings.Fields(values[0])
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			writeInvalidSessionToken(writer, request)
			return
		}
		claims, err := verifier.Verify(fields[1])
		if err != nil {
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
