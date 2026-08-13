package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/starloader/backend/internal/security"
)

func TestRequireSessionRejectsInvalidAuthorizationHeaders(t *testing.T) {
	// These cases fail if authorization parsing accepts a missing, malformed, or unverifiable credential.
	tests := []struct {
		name          string
		authorization string
		verifierErr   error
		wantToken     string
	}{
		{name: "missing header"},
		{name: "wrong scheme", authorization: "Basic signed-token"},
		{name: "blank token", authorization: "Bearer    "},
		{name: "extra authorization field", authorization: "Bearer signed-token extra"},
		{name: "invalid token", authorization: "Bearer invalid-token", verifierErr: errors.New("signature failure"), wantToken: "invalid-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &fakeBearerVerifier{err: tt.verifierErr}
			nextCalled := false
			handler := RequireSession(verifier, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}))
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			if tt.authorization != "" {
				request.Header.Set("Authorization", tt.authorization)
			}

			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
			}
			if nextCalled {
				t.Fatal("downstream handler was called")
			}
			if verifier.token != tt.wantToken {
				t.Fatalf("Verify() token = %q, want %q", verifier.token, tt.wantToken)
			}
			var response errorResponse
			decodeResponse(t, recorder, &response)
			if response.OK || response.Code != "INVALID_SESSION_TOKEN" || response.Message == "" {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestRequireSessionStoresExactVerifiedClaimsInRequestContext(t *testing.T) {
	// This fails if the middleware drops, changes, or invents verified token claims.
	wantClaims := security.SessionClaims{
		Subject: "user-1", LicenseID: "license-1", DeviceID: "device-1", Product: "StarLoader",
		Features: []string{"profile"}, Issuer: "starloader", Audience: "starloader-client",
		IssuedAt: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC),
	}
	verifier := &fakeBearerVerifier{claims: wantClaims}
	var gotClaims security.SessionClaims
	var found bool
	handler := RequireSession(verifier, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		gotClaims, found = SessionClaimsFromContext(request.Context())
	}))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	request.Header.Set("Authorization", "bEaReR signed-token")

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if verifier.token != "signed-token" {
		t.Fatalf("Verify() token = %q", verifier.token)
	}
	if !found || gotClaims.Subject != wantClaims.Subject || gotClaims.LicenseID != wantClaims.LicenseID || gotClaims.DeviceID != wantClaims.DeviceID || gotClaims.Product != wantClaims.Product || gotClaims.Issuer != wantClaims.Issuer || gotClaims.Audience != wantClaims.Audience || !gotClaims.IssuedAt.Equal(wantClaims.IssuedAt) || !gotClaims.ExpiresAt.Equal(wantClaims.ExpiresAt) || len(gotClaims.Features) != 1 || gotClaims.Features[0] != "profile" {
		t.Fatalf("SessionClaimsFromContext() = %#v, found = %t", gotClaims, found)
	}
	if _, found := SessionClaimsFromContext(context.Background()); found {
		t.Fatal("claims unexpectedly found in an unrelated context")
	}
}

type fakeBearerVerifier struct {
	claims security.SessionClaims
	err    error
	token  string
}

func (fake *fakeBearerVerifier) Verify(token string) (security.SessionClaims, error) {
	fake.token = token
	return fake.claims, fake.err
}
