package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

func TestMeReturnsLiteralSafeProfileSelectedByVerifiedClaims(t *testing.T) {
	// This fails if the endpoint omits or adds fields, trusts request IDs, or uses any time other than the verified token expiry.
	claims := validMeClaims()
	repository := &fakeProfileRepository{profile: validMeProfile()}
	verifier := &fakeBearerVerifier{claims: claims}
	router := NewRouter(RouterConfig{
		SessionVerifier: verifier,
		Profile:         repository,
		Now:             func() time.Time { return time.Date(2026, 8, 13, 18, 0, 0, 0, time.UTC) },
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/me?user_id=attacker&license_id=attacker&device_id=attacker", nil)
	request.Header.Set("Authorization", "Bearer memory-only-session-token")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var got map[string]any
	decodeResponse(t, recorder, &got)
	var want map[string]any
	if err := json.Unmarshal([]byte(`{
		"ok": true,
		"email": "test2@test.com",
		"account_status": "active",
		"product": "StarLoader",
		"license_status": "active",
		"license_expires_at": "2026-09-12T17:42:56Z",
		"max_devices": 1,
		"device_id": "019ffc3f-0396-7266-b82c-35371486cc4e",
		"device_status": "active",
		"session_expires_at": "2026-08-13T18:50:15Z"
	}`), &want); err != nil {
		t.Fatalf("decode literal expected response: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response = %#v, want %#v", got, want)
	}
	if verifier.token != "memory-only-session-token" {
		t.Fatalf("Verify() token = %q", verifier.token)
	}
	if repository.calls != 1 || repository.userID != claims.Subject || repository.licenseID != claims.LicenseID || repository.deviceID != claims.DeviceID {
		t.Fatalf("LoadProfile() calls = %d, IDs = (%q, %q, %q)", repository.calls, repository.userID, repository.licenseID, repository.deviceID)
	}
	if strings.Contains(recorder.Body.String(), "memory-only-session-token") {
		t.Fatal("response leaked the session token")
	}
}

func TestMeMapsInactiveMismatchedAndRepositoryFailuresToSafeErrors(t *testing.T) {
	// Each case fails if a stale authorization state is accepted or an internal/sensitive value escapes in an error.
	now := time.Date(2026, 8, 13, 18, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		profile *domain.UserProfile
		err     error
		status  int
		code    string
	}{
		{name: "disabled account", profile: mutateMeProfile(func(profile *domain.UserProfile) { profile.AccountStatus = domain.UserStatusDisabled }), status: http.StatusUnauthorized, code: "INVALID_SESSION_TOKEN"},
		{name: "expired license state", profile: mutateMeProfile(func(profile *domain.UserProfile) { profile.LicenseStatus = domain.LicenseStatusExpired }), status: http.StatusForbidden, code: "LICENSE_EXPIRED"},
		{name: "elapsed active license", profile: mutateMeProfile(func(profile *domain.UserProfile) { profile.LicenseExpiresAt = now }), status: http.StatusForbidden, code: "LICENSE_EXPIRED"},
		{name: "revoked license", profile: mutateMeProfile(func(profile *domain.UserProfile) { profile.LicenseStatus = domain.LicenseStatusRevoked }), status: http.StatusForbidden, code: "LICENSE_REVOKED"},
		{name: "revoked device", profile: mutateMeProfile(func(profile *domain.UserProfile) { profile.DeviceStatus = domain.DeviceStatusRevoked }), status: http.StatusForbidden, code: "DEVICE_REVOKED"},
		{name: "mismatched device", profile: mutateMeProfile(func(profile *domain.UserProfile) { profile.DeviceID = "019ffc3f-0396-7266-b82c-35371486ffff" }), status: http.StatusUnauthorized, code: "INVALID_SESSION_TOKEN"},
		{name: "mismatched product", profile: mutateMeProfile(func(profile *domain.UserProfile) { profile.Product = "OtherProduct" }), status: http.StatusUnauthorized, code: "INVALID_SESSION_TOKEN"},
		{name: "mismatched records", err: domain.ErrProfileNotFound, status: http.StatusUnauthorized, code: "INVALID_SESSION_TOKEN"},
		{name: "repository error", err: errors.New("database password=secret license=plaintext hmac=tpm raw-serial"), status: http.StatusInternalServerError, code: "SERVER_ERROR"},
		{name: "nil repository record", status: http.StatusInternalServerError, code: "SERVER_ERROR"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeProfileRepository{profile: test.profile, err: test.err}
			router := NewRouter(RouterConfig{
				SessionVerifier: &fakeBearerVerifier{claims: validMeClaims()},
				Profile:         repository,
				Now:             func() time.Time { return now },
			})
			request := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			request.Header.Set("Authorization", "Bearer private-session-token")
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			assertErrorResponse(t, recorder, test.status, test.code)
			lowerBody := strings.ToLower(recorder.Body.String())
			for _, forbidden := range []string{
				"test2@test.com", "private-session-token", "password", "plaintext", "hmac", "tpm", "raw-serial",
			} {
				if strings.Contains(lowerBody, forbidden) {
					t.Fatalf("error response leaked %q: %s", forbidden, recorder.Body.String())
				}
			}
		})
	}
}

func TestRouterMeRequiresBearerOnlyForGETAndRejectsOtherMethods(t *testing.T) {
	// This fails if /v1/me becomes public or if a non-GET method reaches authentication/profile work.
	repository := &fakeProfileRepository{profile: validMeProfile()}
	verifier := &fakeBearerVerifier{claims: validMeClaims()}
	router := NewRouter(RouterConfig{SessionVerifier: verifier, Profile: repository})

	unauthorized := httptest.NewRecorder()
	router.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	assertErrorResponse(t, unauthorized, http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
	if repository.calls != 0 {
		t.Fatalf("unauthorized request caused %d profile calls", repository.calls)
	}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			request := httptest.NewRequest(method, "/v1/me", nil)
			request.Header.Set("Authorization", "Bearer memory-only-session-token")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			assertErrorResponse(t, recorder, http.StatusMethodNotAllowed, "INVALID_REQUEST")
		})
	}
	if verifier.token != "" || repository.calls != 0 {
		t.Fatalf("non-GET requests reached dependencies: verified token = %q, profile calls = %d", verifier.token, repository.calls)
	}
}

type fakeProfileRepository struct {
	profile   *domain.UserProfile
	err       error
	userID    string
	licenseID string
	deviceID  string
	calls     int
}

func (fake *fakeProfileRepository) LoadProfile(_ context.Context, userID, licenseID, deviceID string) (*domain.UserProfile, error) {
	fake.calls++
	fake.userID = userID
	fake.licenseID = licenseID
	fake.deviceID = deviceID
	return fake.profile, fake.err
}

func validMeClaims() security.SessionClaims {
	return security.SessionClaims{
		Subject: "user-from-verified-claims", LicenseID: "license-from-verified-claims",
		DeviceID: "019ffc3f-0396-7266-b82c-35371486cc4e", Product: "StarLoader",
		Issuer: "starloader", Audience: "starloader-client",
		IssuedAt:  time.Date(2026, 8, 13, 17, 50, 15, 0, time.UTC),
		ExpiresAt: time.Date(2026, 8, 13, 18, 50, 15, 0, time.UTC),
	}
}

func validMeProfile() *domain.UserProfile {
	return &domain.UserProfile{
		Email: "test2@test.com", AccountStatus: domain.UserStatusActive,
		Product: "StarLoader", LicenseStatus: domain.LicenseStatusActive,
		LicenseExpiresAt: time.Date(2026, 9, 12, 17, 42, 56, 0, time.UTC), MaxDevices: 1,
		DeviceID: "019ffc3f-0396-7266-b82c-35371486cc4e", DeviceStatus: domain.DeviceStatusActive,
	}
}

func mutateMeProfile(mutate func(*domain.UserProfile)) *domain.UserProfile {
	profile := validMeProfile()
	mutate(profile)
	return profile
}
