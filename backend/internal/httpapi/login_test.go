package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/starloader/backend/internal/service"
)

func TestLoginReturnsChallengeAndCorrelatedUUIDv7RequestID(t *testing.T) {
	expiresAt := time.Date(2026, 8, 10, 9, 32, 0, 0, time.UTC)
	login := &fakeLoginService{pending: service.PendingChallenge{
		SessionID: "session-1",
		Challenge: []byte("01234567890123456789012345678901"),
		ExpiresAt: expiresAt,
	}}
	router := NewRouter(RouterConfig{Login: login})
	req := loginRequest(`{"email":" PERSON@Example.COM ","password":"secret","device_fingerprint":"fingerprint"}`)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	requestID := rr.Header().Get("X-Request-ID")
	assertUUIDv7(t, requestID)
	var response struct {
		OK                 bool   `json:"ok"`
		SessionID          string `json:"session_id"`
		Challenge          string `json:"challenge"`
		ChallengeExpiresAt string `json:"challenge_expires_at"`
	}
	decodeResponse(t, rr, &response)
	if !response.OK || response.SessionID != "session-1" || response.Challenge != base64.StdEncoding.EncodeToString(login.pending.Challenge) || response.ChallengeExpiresAt != "2026-08-10T09:32:00Z" {
		t.Fatalf("response = %#v", response)
	}
	if login.input.Email != " PERSON@Example.COM " || login.input.Password != "secret" || login.input.DeviceFingerprint != "fingerprint" {
		t.Fatalf("Login() input = %#v", login.input)
	}
}

func TestLoginRejectsLegacyLicenseKeyField(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
	req := loginRequest(`{"email":"a@b.c","password":"x","device_fingerprint":"F","license_key":"K"}`)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertErrorResponse(t, rr, http.StatusBadRequest, "INVALID_REQUEST")
}

func TestLoginRejectsUnknownJSONField(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
	req := loginRequest(`{"email":"a@b.c","password":"x","device_fingerprint":"F","extra":true}`)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertErrorResponse(t, rr, http.StatusBadRequest, "INVALID_REQUEST")
}

func TestLoginRejectsMultipleJSONValues(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
	req := loginRequest(`{"email":"a@b.c","password":"x","device_fingerprint":"F"} {}`)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertErrorResponse(t, rr, http.StatusBadRequest, "INVALID_REQUEST")
}

func TestLoginRequiresJSONMediaType(t *testing.T) {
	for _, contentType := range []string{"", "text/plain", "application/json-patch+json"} {
		t.Run(contentType, func(t *testing.T) {
			router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(validLoginJSON))
			req.Header.Set("Content-Type", contentType)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assertErrorResponse(t, rr, http.StatusUnsupportedMediaType, "INVALID_REQUEST")
		})
	}
}

func TestLoginAcceptsJSONMediaTypeParameters(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
	req := loginRequest(validLoginJSON)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestLoginRejectsBodyLargerThan64KiB(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
	req := loginRequest(`{"email":"a@b.c","password":"` + strings.Repeat("x", 64*1024) + `","device_fingerprint":"F"}`)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertErrorResponse(t, rr, http.StatusRequestEntityTooLarge, "INVALID_REQUEST")
}

func TestLoginRejectsMissingRequiredFields(t *testing.T) {
	for _, body := range []string{
		`{"email":"","password":"x","device_fingerprint":"F"}`,
		`{"email":"a@b.c","password":"","device_fingerprint":"F"}`,
		`{"email":"a@b.c","password":"x","device_fingerprint":" "}`,
	} {
		t.Run(body, func(t *testing.T) {
			router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, loginRequest(body))
			assertErrorResponse(t, rr, http.StatusBadRequest, "INVALID_REQUEST")
		})
	}
}

func TestLoginMapsSafeServiceErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "invalid credentials", err: service.ErrInvalidCredentials, status: http.StatusUnauthorized, code: "INVALID_CREDENTIALS"},
		{name: "missing license", err: service.ErrLicenseNotFound, status: http.StatusNotFound, code: "LICENSE_NOT_FOUND"},
		{name: "expired license", err: service.ErrLicenseExpired, status: http.StatusForbidden, code: "LICENSE_EXPIRED"},
		{name: "revoked license", err: service.ErrLicenseRevoked, status: http.StatusForbidden, code: "LICENSE_REVOKED"},
		{name: "random failure", err: service.ErrChallengeGeneration, status: http.StatusInternalServerError, code: "SERVER_ERROR"},
		{name: "repository detail", err: errors.New("find user: database host secret.internal refused connection"), status: http.StatusInternalServerError, code: "SERVER_ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(RouterConfig{Login: &fakeLoginService{err: tt.err}})
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, loginRequest(validLoginJSON))
			response := assertErrorResponse(t, rr, tt.status, tt.code)
			if strings.Contains(response.Message, "database") || strings.Contains(response.Message, "secret.internal") {
				t.Fatalf("response leaks internal error: %#v", response)
			}
		})
	}
}

func TestLoginBoundsServiceWorkWithConfiguredDeadline(t *testing.T) {
	serviceCanceled := make(chan error, 1)
	login := &fakeLoginService{
		loginFunc: func(ctx context.Context, _ service.LoginInput) (service.PendingChallenge, error) {
			<-ctx.Done()
			serviceCanceled <- ctx.Err()
			return service.PendingChallenge{}, ctx.Err()
		},
	}
	router := NewRouter(RouterConfig{
		Login:        login,
		LoginTimeout: 20 * time.Millisecond,
	})
	rr := httptest.NewRecorder()
	startedAt := time.Now()

	router.ServeHTTP(rr, loginRequest(validLoginJSON))

	assertErrorResponse(t, rr, http.StatusInternalServerError, "SERVER_ERROR")
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("login took %s despite configured deadline", elapsed)
	}
	if err := <-serviceCanceled; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("service context error = %v, want deadline exceeded", err)
	}
	if strings.Contains(rr.Body.String(), "deadline") || strings.Contains(rr.Body.String(), "context") {
		t.Fatalf("response leaks cancellation detail: %s", rr.Body.String())
	}
}

func TestRecoveryReturnsServerErrorAndLogsOnlyRequestID(t *testing.T) {
	var logged strings.Builder
	router := NewRouter(RouterConfig{
		Login:  &fakeLoginService{panicValue: "password=do-not-log"},
		Logger: log.New(&logged, "", 0),
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, loginRequest(validLoginJSON))

	response := assertErrorResponse(t, rr, http.StatusInternalServerError, "SERVER_ERROR")
	if !strings.Contains(logged.String(), response.RequestID) {
		t.Fatalf("panic log %q does not contain request ID %q", logged.String(), response.RequestID)
	}
	if strings.Contains(logged.String(), "password") || strings.Contains(logged.String(), "do-not-log") {
		t.Fatalf("panic log leaks panic value: %q", logged.String())
	}
}

func TestEveryRouteResponseCarriesRequestID(t *testing.T) {
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
	tests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/healthz", nil),
		httptest.NewRequest(http.MethodGet, "/missing", nil),
		httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil),
	}
	for _, req := range tests {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assertUUIDv7(t, rr.Header().Get("X-Request-ID"))
	}
}

func TestLoginAllowsFiveAttemptsPerMinutePerDirectIP(t *testing.T) {
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}, Now: func() time.Time { return now }})
	for attempt := 1; attempt <= 6; attempt++ {
		req := loginRequest(validLoginJSON)
		req.RemoteAddr = "203.0.113.9:4000"
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if attempt <= 5 && rr.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d", attempt, rr.Code)
		}
		if attempt == 6 {
			assertErrorResponse(t, rr, http.StatusTooManyRequests, "RATE_LIMITED")
		}
	}
}

func TestUntrustedPeerCannotRotateForwardedIPToBypassLimit(t *testing.T) {
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	router := NewRouter(RouterConfig{Login: &fakeLoginService{}, Now: func() time.Time { return now }})
	for attempt := 1; attempt <= 6; attempt++ {
		req := loginRequest(validLoginJSON)
		req.RemoteAddr = "203.0.113.9:4000"
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('0'+attempt)))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if attempt == 6 {
			assertErrorResponse(t, rr, http.StatusTooManyRequests, "RATE_LIMITED")
		}
	}
}

func TestConfiguredTrustedProxyUsesForwardedClientIP(t *testing.T) {
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	trusted := netip.MustParsePrefix("10.0.0.0/8")
	router := NewRouter(RouterConfig{
		Login:          &fakeLoginService{},
		Now:            func() time.Time { return now },
		TrustedProxies: []netip.Prefix{trusted},
	})
	for attempt := 1; attempt <= 6; attempt++ {
		req := loginRequest(validLoginJSON)
		req.RemoteAddr = "10.0.0.5:4000"
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('0'+attempt)))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("client %d status = %d", attempt, rr.Code)
		}
	}
}

func TestRateLimiterKeepsAttackerControlledKeysBounded(t *testing.T) {
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	limiter := newIPRateLimiter(5, time.Minute, 2, func() time.Time { return now })
	if !limiter.allow("198.51.100.1") || !limiter.allow("198.51.100.2") {
		t.Fatal("limiter rejected keys before reaching capacity")
	}
	if limiter.allow("198.51.100.3") {
		t.Fatal("limiter accepted an attacker-controlled key beyond capacity")
	}
	if got := limiter.size(); got != 2 {
		t.Fatalf("limiter key count = %d, want 2", got)
	}

	now = now.Add(time.Minute)
	if !limiter.allow("198.51.100.3") {
		t.Fatal("limiter did not evict expired buckets")
	}
	if got := limiter.size(); got > 2 {
		t.Fatalf("limiter key count after eviction = %d", got)
	}
}

func TestHealthzReportsDependencyFailureWithoutDetails(t *testing.T) {
	router := NewRouter(RouterConfig{
		Login: &fakeLoginService{},
		HealthCheck: func(context.Context) error {
			return errors.New("database secret.internal is down")
		},
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	response := assertErrorResponse(t, rr, http.StatusServiceUnavailable, "SERVER_ERROR")
	if strings.Contains(response.Message, "database") || strings.Contains(response.Message, "secret.internal") {
		t.Fatalf("health response leaks dependency error: %#v", response)
	}
}

func TestHealthzBoundsDependencyCheckDuration(t *testing.T) {
	healthStarted := make(chan struct{})
	router := NewRouter(RouterConfig{
		Login:              &fakeLoginService{},
		HealthCheckTimeout: 20 * time.Millisecond,
		HealthCheck: func(ctx context.Context) error {
			close(healthStarted)
			<-ctx.Done()
			return ctx.Err()
		},
	})
	rr := httptest.NewRecorder()
	startedAt := time.Now()

	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	<-healthStarted
	assertErrorResponse(t, rr, http.StatusServiceUnavailable, "SERVER_ERROR")
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("health check took %s despite bounded timeout", elapsed)
	}
}

const validLoginJSON = `{"email":"a@b.c","password":"x","device_fingerprint":"F"}`

type fakeLoginService struct {
	pending    service.PendingChallenge
	err        error
	input      service.LoginInput
	panicValue any
	loginFunc  func(context.Context, service.LoginInput) (service.PendingChallenge, error)
}

func (fake *fakeLoginService) Login(ctx context.Context, input service.LoginInput) (service.PendingChallenge, error) {
	if fake.panicValue != nil {
		panic(fake.panicValue)
	}
	fake.input = input
	if fake.loginFunc != nil {
		return fake.loginFunc(ctx, input)
	}
	return fake.pending, fake.err
}

type errorResponse struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func loginRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func assertErrorResponse(t *testing.T, rr *httptest.ResponseRecorder, status int, code string) errorResponse {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, status, rr.Body.String())
	}
	var response errorResponse
	decodeResponse(t, rr, &response)
	if response.OK || response.Code != code || response.Message == "" {
		t.Fatalf("response = %#v", response)
	}
	if response.RequestID == "" || response.RequestID != rr.Header().Get("X-Request-ID") {
		t.Fatalf("response request ID = %q, header = %q", response.RequestID, rr.Header().Get("X-Request-ID"))
	}
	return response
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder, destination any) {
	t.Helper()
	decoder := json.NewDecoder(rr.Body)
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, rr.Body.String())
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("response contains multiple JSON values: %v", err)
	}
}

func assertUUIDv7(t *testing.T, value string) {
	t.Helper()
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[14] != '7' || value[18] != '-' || value[23] != '-' || !strings.Contains("89ab", strings.ToLower(value[19:20])) {
		t.Fatalf("request ID %q is not a UUIDv7", value)
	}
}
