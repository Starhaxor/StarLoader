package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/service/adminauth"
)

type fakeAdminAuth struct {
	token        string
	account      *domain.AdminAccount
	loginErr     error
	loggedOut    []string
	authenticateCalls int
}

func (f *fakeAdminAuth) Login(_ context.Context, email, password, ipAddress, userAgent string) (string, *domain.AdminAccount, error) {
	if f.loginErr != nil {
		return "", nil, f.loginErr
	}
	return f.token, f.account, nil
}

func (f *fakeAdminAuth) Authenticate(_ context.Context, token string) (*domain.AdminSession, *domain.AdminAccount, error) {
	f.authenticateCalls++
	if token == "" || token != f.token || f.account == nil {
		return nil, nil, domain.ErrAdminSessionNotFound
	}
	return &domain.AdminSession{ID: "session-id", AdminAccountID: f.account.ID}, f.account, nil
}

func (f *fakeAdminAuth) Logout(_ context.Context, token string) error {
	f.loggedOut = append(f.loggedOut, token)
	return nil
}

// fakeAdminConsole embeds the interface; tests only exercise the audit path.
type fakeAdminConsole struct {
	AdminConsoleStore
	auditEntries []domain.NewAuditLog
}

func (f *fakeAdminConsole) AppendAuditLog(_ context.Context, input domain.NewAuditLog) error {
	f.auditEntries = append(f.auditEntries, input)
	return nil
}

func newAdminTestRouter(t *testing.T, auth *fakeAdminAuth) (*Router, *fakeAdminConsole) {
	t.Helper()
	console := &fakeAdminConsole{}
	router := NewRouter(RouterConfig{
		Admin: AdminConfig{
			Auth:          auth,
			Console:       console,
			AllowedOrigin: "http://localhost:3000",
			CSRFSecret:    []byte("test-csrf-secret"),
			SessionTTL:    time.Hour,
		},
	})
	return router, console
}

func adminLoginBody(t *testing.T, email, password string) *bytes.Reader {
	t.Helper()
	raw, err := json.Marshal(adminLoginRequest{Email: email, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(raw)
}

func responseCookie(response *http.Response, name string) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func TestAdminLoginSetsSessionAndCSRFCookies(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: &domain.AdminAccount{ID: "admin-id", Email: "root@example.com", Status: domain.AdminStatusActive}}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", adminLoginBody(t, "root@example.com", "password"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	response := recorder.Result()
	sessionCookie := responseCookie(response, adminSessionCookieName)
	if sessionCookie == nil || sessionCookie.Value != "session-token" || !sessionCookie.HttpOnly {
		t.Fatalf("session cookie = %#v", sessionCookie)
	}
	csrfCookie := responseCookie(response, adminCSRFCookieName)
	if csrfCookie == nil || csrfCookie.Value != router.adminCSRFToken("session-token") || csrfCookie.HttpOnly {
		t.Fatalf("csrf cookie = %#v", csrfCookie)
	}
}

func TestAdminLoginRejectsInvalidCredentials(t *testing.T) {
	auth := &fakeAdminAuth{loginErr: adminauth.ErrInvalidCredentials}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", adminLoginBody(t, "root@example.com", "wrong"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Code != "INVALID_CREDENTIALS" {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}
}

func TestAdminMeRequiresSessionCookie(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: &domain.AdminAccount{ID: "admin-id", Email: "root@example.com", Status: domain.AdminStatusActive}}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/me", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("without cookie: status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/admin/me", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("with cookie: status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Email != "root@example.com" {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}
}

func TestAdminLogoutRequiresCSRFHeader(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: &domain.AdminAccount{ID: "admin-id", Email: "root@example.com", Status: domain.AdminStatusActive}}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("without csrf: status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(auth.loggedOut) != 0 {
		t.Fatal("logout must not run when CSRF verification fails")
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/admin/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	request.Header.Set(adminCSRFHeader, router.adminCSRFToken("session-token"))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("with csrf: status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(auth.loggedOut) != 1 || auth.loggedOut[0] != "session-token" {
		t.Fatalf("loggedOut = %#v", auth.loggedOut)
	}
	if cookie := responseCookie(recorder.Result(), adminSessionCookieName); cookie == nil || cookie.MaxAge != -1 {
		t.Fatalf("session cookie was not cleared: %#v", cookie)
	}
}

func TestAdminCORSPreflightAllowsConfiguredOrigin(t *testing.T) {
	auth := &fakeAdminAuth{}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodOptions, "/v1/admin/overview", nil)
	request.Header.Set("Origin", "http://localhost:3000")
	request.Header.Set("Access-Control-Request-Method", "GET")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}

	request = httptest.NewRequest(http.MethodOptions, "/v1/admin/overview", nil)
	request.Header.Set("Origin", "http://evil.example")
	request.Header.Set("Access-Control-Request-Method", "GET")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unexpected Access-Control-Allow-Origin header for disallowed origin")
	}
}

func TestAdminUnknownPathReturnsNotFound(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: &domain.AdminAccount{ID: "admin-id", Email: "root@example.com", Status: domain.AdminStatusActive}}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/nope", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminNamespaceDisabledWithoutDependencies(t *testing.T) {
	router := NewRouter(RouterConfig{})
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", adminLoginBody(t, "root@example.com", "password"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}
