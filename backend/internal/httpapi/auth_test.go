package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
		{name: "invalid token", authorization: "DPoP invalid-token", verifierErr: errors.New("signature failure"), wantToken: "invalid-token"},
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

type fakeBearerVerifier struct {
	claims security.SessionClaims
	err    error
	token  string
}

func (fake *fakeBearerVerifier) Verify(token string) (security.SessionClaims, error) {
	fake.token = token
	return fake.claims, fake.err
}

func TestRequireSessionRejectsStolenBearerWithoutDeviceProof(t *testing.T) {
	handler := RequireSession(&fakeBearerVerifier{claims: security.SessionClaims{Subject: "victim"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest("GET", "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer stolen-valid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stolen bearer admitted: %d", rec.Code)
	}
}
