package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/service"
)

func TestDeviceVerifyReturnsBoundSessionToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	verification := &fakeDeviceVerificationService{verified: service.VerifiedSession{
		Token: "signed-token", ExpiresAt: now.Add(time.Hour), LicenseID: "license-1", DeviceID: "device-1",
	}}
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}, DeviceVerification: verification})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, deviceVerifyRequest(validDeviceVerifyJSON))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		OK             bool   `json:"ok"`
		Token          string `json:"token"`
		TokenExpiresAt string `json:"token_expires_at"`
		LicenseID      string `json:"license_id"`
		DeviceID       string `json:"device_id"`
	}
	decodeResponse(t, recorder, &response)
	if !response.OK || response.Token != "signed-token" || response.TokenExpiresAt != now.Add(time.Hour).Format(time.RFC3339) || response.LicenseID != "license-1" || response.DeviceID != "device-1" {
		t.Fatalf("response = %#v", response)
	}
	if verification.input.SessionID != "11111111-1111-4111-8111-111111111111" || verification.input.Hardware.SystemDiskSerial != "disk-raw" || verification.input.ChallengeSignature != "c2lnbmF0dXJl" {
		t.Fatalf("Verify() input = %#v", verification.input)
	}
}

func TestDeviceVerifyRejectsMalformedRequests(t *testing.T) {
	missingHardware := strings.Replace(validDeviceVerifyJSON, `"fingerprint":"fingerprint-raw"`, `"fingerprint":""`, 1)
	unknownField := strings.Replace(validDeviceVerifyJSON, `"session_id":"11111111-1111-4111-8111-111111111111"`, `"session_id":"11111111-1111-4111-8111-111111111111","unknown":true`, 1)
	invalidSessionID := strings.Replace(validDeviceVerifyJSON, "11111111-1111-4111-8111-111111111111", "not-a-uuid", 1)
	nonCanonicalSessionID := strings.Replace(validDeviceVerifyJSON, "11111111-1111-4111-8111-111111111111", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", 1)
	for _, test := range []struct {
		name        string
		body        string
		contentType string
		status      int
	}{
		{name: "missing field", body: missingHardware, contentType: "application/json", status: http.StatusBadRequest},
		{name: "invalid session UUID", body: invalidSessionID, contentType: "application/json", status: http.StatusBadRequest},
		{name: "noncanonical session UUID", body: nonCanonicalSessionID, contentType: "application/json", status: http.StatusBadRequest},
		{name: "unknown field", body: unknownField, contentType: "application/json", status: http.StatusBadRequest},
		{name: "multiple values", body: validDeviceVerifyJSON + `{}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "wrong media type", body: validDeviceVerifyJSON, contentType: "text/plain", status: http.StatusUnsupportedMediaType},
		{name: "oversized body", body: validDeviceVerifyJSON + strings.Repeat(" ", 64*1024), contentType: "application/json", status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			verification := &fakeDeviceVerificationService{}
			router := NewRouter(RouterConfig{Login: &fakeLoginService{}, DeviceVerification: verification})
			request := httptest.NewRequest(http.MethodPost, "/v1/device/verify", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			assertErrorResponse(t, recorder, test.status, "INVALID_REQUEST")
			if verification.calls != 0 {
				t.Fatal("malformed request reached service")
			}
		})
	}
}

func TestDeviceVerifyMapsSafeServiceErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "expired", err: service.ErrChallengeExpired, status: http.StatusGone, code: "CHALLENGE_EXPIRED"},
		{name: "consumed", err: domain.ErrChallengeConsumed, status: http.StatusConflict, code: "CHALLENGE_CONSUMED"},
		{name: "invalid signature", err: service.ErrInvalidDeviceSignature, status: http.StatusUnauthorized, code: "INVALID_DEVICE_SIGNATURE"},
		{name: "limit", err: service.ErrDeviceLimitReached, status: http.StatusForbidden, code: "DEVICE_LIMIT_REACHED"},
		{name: "device revoked", err: service.ErrDeviceRevoked, status: http.StatusForbidden, code: "DEVICE_REVOKED"},
		{name: "license revoked", err: service.ErrLicenseRevoked, status: http.StatusForbidden, code: "LICENSE_REVOKED"},
		{name: "invalid request", err: service.ErrInvalidVerifyRequest, status: http.StatusBadRequest, code: "INVALID_REQUEST"},
		{name: "internal", err: errors.New("database secret.internal failed"), status: http.StatusInternalServerError, code: "SERVER_ERROR"},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := NewRouter(RouterConfig{Login: &fakeLoginService{}, DeviceVerification: &fakeDeviceVerificationService{err: test.err}})
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, deviceVerifyRequest(validDeviceVerifyJSON))
			response := assertErrorResponse(t, recorder, test.status, test.code)
			if strings.Contains(response.Message, "database") || strings.Contains(response.Message, "secret.internal") {
				t.Fatalf("response leaked internal detail: %#v", response)
			}
		})
	}
}

func TestDeviceVerifyAllowsTenAttemptsPerMinutePerSession(t *testing.T) {
	now := time.Now().UTC()
	verification := &fakeDeviceVerificationService{}
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}, DeviceVerification: verification, Now: func() time.Time { return now }})
	for attempt := 1; attempt <= 11; attempt++ {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, deviceVerifyRequest(validDeviceVerifyJSON))
		if attempt <= 10 && recorder.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d", attempt, recorder.Code)
		}
		if attempt == 11 {
			assertErrorResponse(t, recorder, http.StatusTooManyRequests, "RATE_LIMITED")
		}
	}
	if verification.calls != 10 {
		t.Fatalf("service calls = %d, want 10", verification.calls)
	}
}

func TestDeviceVerifyRejectsOverlongSessionBeforeRateLimiter(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}, DeviceVerification: &fakeDeviceVerificationService{}})
	body := strings.Replace(validDeviceVerifyJSON, "11111111-1111-4111-8111-111111111111", strings.Repeat("s", 129), 1)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, deviceVerifyRequest(body))

	assertErrorResponse(t, recorder, http.StatusBadRequest, "INVALID_REQUEST")
	if got := router.sessionLimiter.size(); got != 0 {
		t.Fatalf("rate limiter retained %d invalid session keys", got)
	}
}

func TestDeviceVerifyBoundsServiceWorkWithConfiguredDeadline(t *testing.T) {
	serviceCanceled := make(chan error, 1)
	verification := &fakeDeviceVerificationService{verifyFunc: func(ctx context.Context, _ service.VerifyInput) (service.VerifiedSession, error) {
		<-ctx.Done()
		serviceCanceled <- ctx.Err()
		return service.VerifiedSession{}, ctx.Err()
	}}
	router := NewRouter(RouterConfig{
		Login: &fakeLoginService{}, DeviceVerification: verification, DeviceVerifyTimeout: 20 * time.Millisecond,
	})
	recorder := httptest.NewRecorder()
	started := time.Now()

	router.ServeHTTP(recorder, deviceVerifyRequest(validDeviceVerifyJSON))

	assertErrorResponse(t, recorder, http.StatusInternalServerError, "SERVER_ERROR")
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("device verification exceeded configured deadline")
	}
	if err := <-serviceCanceled; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("service context error = %v", err)
	}
}

func TestDeviceVerifyRouteRejectsWrongMethod(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}, DeviceVerification: &fakeDeviceVerificationService{}})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/device/verify", nil))
	assertErrorResponse(t, recorder, http.StatusMethodNotAllowed, "INVALID_REQUEST")
}

const validDeviceVerifyJSON = `{"session_id":"11111111-1111-4111-8111-111111111111","challenge":"Y2hhbGxlbmdl","challenge_signature":"c2lnbmF0dXJl","tpm_public_key":"cHVibGljLWtleQ==","hardware":{"smbios_uuid":"smbios-raw","motherboard_serial":"board-raw","bios_serial":"bios-raw","system_disk_serial":"disk-raw","machine_guid":"guid-raw","fingerprint":"fingerprint-raw"}}`

type fakeDeviceVerificationService struct {
	verified   service.VerifiedSession
	err        error
	input      service.VerifyInput
	calls      int
	verifyFunc func(context.Context, service.VerifyInput) (service.VerifiedSession, error)
}

func (fake *fakeDeviceVerificationService) Verify(ctx context.Context, input service.VerifyInput) (service.VerifiedSession, error) {
	fake.calls++
	fake.input = input
	if fake.verifyFunc != nil {
		return fake.verifyFunc(ctx, input)
	}
	return fake.verified, fake.err
}

func deviceVerifyRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/device/verify", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}
