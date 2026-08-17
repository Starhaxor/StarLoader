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

var testOwnerPermissions = []string{
	domain.PermOverviewRead, domain.PermUsersRead, domain.PermUsersWrite,
	domain.PermLicensesRead, domain.PermLicensesWrite, domain.PermDevicesRead,
	domain.PermDevicesWrite, domain.PermSessionsRead, domain.PermSessionsWrite,
	domain.PermAuditRead, domain.PermSecurityRead, domain.PermAdminsRead, domain.PermAdminsWrite,
}

func testOwnerAccount() *domain.AdminAccount {
	return &domain.AdminAccount{
		ID:          "admin-id",
		Email:       "root@example.com",
		Status:      domain.AdminStatusActive,
		RoleName:    domain.RoleOwner,
		Permissions: testOwnerPermissions,
		MFAEnrolled: true,
	}
}

type fakeAdminAuth struct {
	token           string
	account         *domain.AdminAccount
	loginErr        error
	loginResult     *adminauth.LoginResult
	completeMFAToken string
	completeMFAErr  error
	loggedOut       []string
	authenticateCalls int
}

func (f *fakeAdminAuth) Login(_ context.Context, email, password, ipAddress, userAgent string) (adminauth.LoginResult, error) {
	if f.loginErr != nil {
		return adminauth.LoginResult{}, f.loginErr
	}
	if f.loginResult != nil {
		return *f.loginResult, nil
	}
	return adminauth.LoginResult{Token: f.token, Account: f.account}, nil
}

func (f *fakeAdminAuth) CompleteMFA(_ context.Context, challengeToken, code, recoveryCode, ipAddress, userAgent string) (string, *domain.AdminAccount, error) {
	if f.completeMFAErr != nil {
		return "", nil, f.completeMFAErr
	}
	token := f.completeMFAToken
	if token == "" {
		token = f.token
	}
	return token, f.account, nil
}

func (f *fakeAdminAuth) StartMFAEnrollment(_ context.Context, account *domain.AdminAccount, issuer string) (string, string, error) {
	return "TESTSECRET", "otpauth://totp/Test?secret=TESTSECRET", nil
}

func (f *fakeAdminAuth) ConfirmMFAEnrollment(_ context.Context, account *domain.AdminAccount, code, ipAddress, userAgent string) ([]string, error) {
	if code != "123456" {
		return nil, adminauth.ErrInvalidMFACode
	}
	return []string{"AAAA-BBBB"}, nil
}

func (f *fakeAdminAuth) DisableMFA(_ context.Context, account *domain.AdminAccount, password, ipAddress, userAgent string) error {
	if password != "correct password" {
		return adminauth.ErrInvalidCredentials
	}
	return nil
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

// fakeAdminConsole embeds the interface; tests only exercise the audit and
// security event paths.
type fakeAdminConsole struct {
	AdminConsoleStore
	auditEntries    []domain.NewAuditLog
	securityEvents  []domain.NewSecurityEvent
}

func (f *fakeAdminConsole) AppendAuditLog(_ context.Context, input domain.NewAuditLog) error {
	f.auditEntries = append(f.auditEntries, input)
	return nil
}

func (f *fakeAdminConsole) AppendSecurityEvent(_ context.Context, input domain.NewSecurityEvent) error {
	f.securityEvents = append(f.securityEvents, input)
	return nil
}

func newAdminTestRouter(t *testing.T, auth *fakeAdminAuth) (*Router, *fakeAdminConsole) {
	t.Helper()
	console := &fakeAdminConsole{}
	router := NewRouter(RouterConfig{
		Admin: AdminConfig{
			Auth:          auth,
			Console:       console,
			AllowedOrigins: []string{"http://localhost:3000"},
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
	auth := &fakeAdminAuth{token: "session-token", account: testOwnerAccount()}
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

func TestAdminLoginReturnsChallengeForEnrolledAccounts(t *testing.T) {
	auth := &fakeAdminAuth{
		account: testOwnerAccount(),
		loginResult: &adminauth.LoginResult{
			ChallengeToken: "challenge-token",
			MFARequired:    true,
			Account:        testOwnerAccount(),
		},
	}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", adminLoginBody(t, "root@example.com", "password"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if cookie := responseCookie(recorder.Result(), adminSessionCookieName); cookie != nil && cookie.MaxAge > 0 {
		t.Fatal("session cookie must not be set before MFA completion")
	}
	var body struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || !body.MFARequired || body.MFAToken != "challenge-token" {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}
}

func TestAdminMFACompletesLoginWithValidCode(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: testOwnerAccount()}
	router, _ := newAdminTestRouter(t, auth)

	raw, err := json.Marshal(adminMFARequest{MFAToken: "challenge-token", Code: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/mfa", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	cookie := responseCookie(recorder.Result(), adminSessionCookieName)
	if cookie == nil || cookie.Value != "session-token" {
		t.Fatalf("session cookie = %#v", cookie)
	}
}

func TestAdminMFARejectsExpiredChallenge(t *testing.T) {
	auth := &fakeAdminAuth{account: testOwnerAccount(), completeMFAErr: adminauth.ErrMFAChallengeExpired}
	router, _ := newAdminTestRouter(t, auth)

	raw, err := json.Marshal(adminMFARequest{MFAToken: "stale-token", Code: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/mfa", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Code != "MFA_CHALLENGE_EXPIRED" {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}
}

func TestAdminLoginRejectsInvalidCredentials(t *testing.T) {
	auth := &fakeAdminAuth{loginErr: adminauth.ErrInvalidCredentials}
	router, console := newAdminTestRouter(t, auth)

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
	if len(console.securityEvents) != 1 || console.securityEvents[0].Kind != "ADMIN_LOGIN_FAILED" {
		t.Fatalf("security events = %#v, want one login failure", console.securityEvents)
	}
}

func TestAdminMeRequiresSessionCookie(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: testOwnerAccount()}
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
		Email       string   `json:"email"`
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
		MFAEnrolled bool     `json:"mfa_enrolled"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Email != "root@example.com" || body.Role != domain.RoleOwner || len(body.Permissions) == 0 || !body.MFAEnrolled {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}
}

func TestAdminUnenrolledAccountIsGatedToEnrollmentFlow(t *testing.T) {
	account := testOwnerAccount()
	account.MFAEnrolled = false
	auth := &fakeAdminAuth{token: "session-token", account: account}
	router, _ := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/overview", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("overview status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Code != "MFA_ENROLLMENT_REQUIRED" {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}

	// The enrollment start endpoint stays reachable for unenrolled accounts.
	request = httptest.NewRequest(http.MethodPost, "/v1/admin/mfa/enroll/start", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	request.Header.Set(adminCSRFHeader, router.adminCSRFToken("session-token"))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("enroll start status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminPermissionDeniedForMissingPermission(t *testing.T) {
	account := testOwnerAccount()
	account.Permissions = []string{domain.PermOverviewRead}
	auth := &fakeAdminAuth{token: "session-token", account: account}
	router, console := newAdminTestRouter(t, auth)

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Code != "PERMISSION_DENIED" {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}
	found := false
	for _, event := range console.securityEvents {
		if event.Kind == "ADMIN_PERMISSION_DENIED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("security events = %#v, want permission denial", console.securityEvents)
	}
}

func TestAdminLogoutRequiresCSRFHeader(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: testOwnerAccount()}
	router, console := newAdminTestRouter(t, auth)

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
	found := false
	for _, event := range console.securityEvents {
		if event.Kind == "ADMIN_CSRF_REJECTED" {
			found = true
		}
	}
	if !found {
		t.Fatal("csrf rejection must be recorded as a security event")
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

type fakeStatsConsole struct {
	AdminConsoleStore
	stats []domain.DailyStat
}

func (f *fakeStatsConsole) ConsoleDailyStats(_ context.Context, days int) ([]domain.DailyStat, error) {
	return f.stats, nil
}

func TestAdminOverviewStatsReturnsSeries(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: testOwnerAccount()}
	console := &fakeStatsConsole{stats: []domain.DailyStat{
		{Day: "2026-08-17", LicensesCreated: 2, AdminLogins: 3},
	}}
	router := NewRouter(RouterConfig{
		Admin: AdminConfig{
			Auth: auth, Console: console, AllowedOrigins: []string{"http://localhost:3000"},
			CSRFSecret: []byte("test-csrf-secret"), SessionTTL: time.Hour,
		},
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/overview/stats", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "session-token"})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		OK   bool           `json:"ok"`
		Days []dailyStatJSON `json:"days"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || !body.OK || len(body.Days) != 1 {
		t.Fatalf("body = %s, err = %v", recorder.Body.String(), err)
	}
	if body.Days[0].LicensesCreated != 2 || body.Days[0].AdminLogins != 3 {
		t.Fatalf("days = %#v", body.Days)
	}
}

func TestAdminUnknownPathReturnsNotFound(t *testing.T) {
	auth := &fakeAdminAuth{token: "session-token", account: testOwnerAccount()}
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
