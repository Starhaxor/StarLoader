package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/service/adminauth"
)

const (
	adminSessionCookieName = "starloader_admin_session"
	adminCSRFCookieName    = "starloader_admin_csrf"
	adminCSRFHeader        = "X-CSRF-Token"
	adminPathPrefix        = "/v1/admin"
	defaultMFAIssuer       = "KeyStar Admin"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AdminAuthService authenticates dashboard administrators and manages their
// TOTP enrollment.
type AdminAuthService interface {
	Login(ctx context.Context, email, password, ipAddress, userAgent string) (adminauth.LoginResult, error)
	CompleteMFA(ctx context.Context, challengeToken, code, recoveryCode, ipAddress, userAgent string) (string, *domain.AdminAccount, error)
	StartMFAEnrollment(ctx context.Context, account *domain.AdminAccount, issuer string) (string, string, error)
	ConfirmMFAEnrollment(ctx context.Context, account *domain.AdminAccount, code, ipAddress, userAgent string) ([]string, error)
	DisableMFA(ctx context.Context, account *domain.AdminAccount, password, ipAddress, userAgent string) error
	Authenticate(ctx context.Context, token string) (*domain.AdminSession, *domain.AdminAccount, error)
	Logout(ctx context.Context, token string) error
}

// AdminConsoleStore is the persistence boundary for dashboard management.
type AdminConsoleStore interface {
	ConsoleOverview(ctx context.Context) (*domain.ConsoleOverview, error)
	ConsoleDailyStats(ctx context.Context, days int) ([]domain.DailyStat, error)
	ListConsoleUsers(ctx context.Context, offset, limit int, search string) ([]domain.ConsoleUser, int64, error)
	ConsoleUserDetail(ctx context.Context, userID string) (*domain.ConsoleUserDetail, error)
	SetUserStatus(ctx context.Context, userID string, status domain.UserStatus) error
	FindUserByEmail(ctx context.Context, email string) (*domain.User, error)
	FindUserByID(ctx context.Context, userID string) (*domain.User, error)
	SetUserPassword(ctx context.Context, userID, passwordHash string) error
	CreateUser(ctx context.Context, input domain.NewUser) (*domain.User, error)
	RevokeUserSessions(ctx context.Context, userID string) (int64, error)
	ListConsoleLicenses(ctx context.Context, offset, limit int) ([]domain.ConsoleLicense, int64, error)
	CreateLicense(ctx context.Context, input domain.NewLicense) (*domain.License, error)
	FindLicenseByID(ctx context.Context, licenseID string) (*domain.License, error)
	AdminUpdateLicense(ctx context.Context, licenseID string, expiresAt time.Time, maxDevices int) error
	AdminRevokeLicense(ctx context.Context, licenseID string) error
	ListConsoleDevices(ctx context.Context, offset, limit int) ([]domain.ConsoleDevice, int64, error)
	FindConsoleDeviceByID(ctx context.Context, deviceID string) (*domain.ConsoleDeviceDetail, error)
	AdminRevokeDevice(ctx context.Context, deviceID string) error
	AdminResetDevice(ctx context.Context, deviceID string) error
	ListConsoleSessions(ctx context.Context, offset, limit int) ([]domain.ConsoleSession, int64, error)
	AdminRevokeAuthSession(ctx context.Context, sessionID string) error
	ListAuditLogs(ctx context.Context, offset, limit int) ([]domain.AuditLog, int64, error)
	AppendAuditLog(ctx context.Context, input domain.NewAuditLog) error
	ListAdminAccounts(ctx context.Context) ([]domain.AdminAccount, error)
	FindAdminAccountByID(ctx context.Context, adminID string) (*domain.AdminAccount, error)
	CreateAdminAccount(ctx context.Context, input domain.NewAdminAccount) (*domain.AdminAccount, error)
	UpdateAdminAccountStatusAndRole(ctx context.Context, adminID string, status domain.AdminAccountStatus, roleName string) error
	SetAdminPassword(ctx context.Context, adminID, passwordHash string) error
	RevokeAllAdminSessions(ctx context.Context, adminID string) error
	ListRoles(ctx context.Context) ([]domain.Role, error)
	ListSecurityEvents(ctx context.Context, offset, limit int) ([]domain.SecurityEvent, int64, error)
	AppendSecurityEvent(ctx context.Context, input domain.NewSecurityEvent) error
}

// AdminConfig bundles the dependencies of the /v1/admin namespace. The
// namespace stays disabled unless both Auth and Console are provided.
type AdminConfig struct {
	Auth           AdminAuthService
	Console        AdminConsoleStore
	LicenseHMACKey []byte
	Product        string
	MFAIssuer      string
	AllowedOrigins []string
	CSRFSecret     []byte
	CookieSecure   bool
	SessionTTL     time.Duration
}

func (router *Router) adminEnabled() bool {
	return router.admin.Auth != nil && router.admin.Console != nil
}

func (router *Router) adminMFAIssuer() string {
	if strings.TrimSpace(router.admin.MFAIssuer) != "" {
		return router.admin.MFAIssuer
	}
	return defaultMFAIssuer
}

func (router *Router) serveAdmin(writer http.ResponseWriter, request *http.Request) {
	origin := request.Header.Get("Origin")
	originAllowed := origin != "" && slices.Contains(router.admin.AllowedOrigins, origin)
	if request.Method == http.MethodOptions {
		if originAllowed && request.Header.Get("Access-Control-Request-Method") != "" {
			header := writer.Header()
			header.Set("Access-Control-Allow-Origin", origin)
			header.Set("Access-Control-Allow-Credentials", "true")
			header.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			header.Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			header.Set("Access-Control-Max-Age", "600")
			header.Add("Vary", "Origin")
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(writer, request, http.StatusMethodNotAllowed, "INVALID_REQUEST", "method not allowed")
		return
	}
	if originAllowed {
		header := writer.Header()
		header.Set("Access-Control-Allow-Origin", origin)
		header.Set("Access-Control-Allow-Credentials", "true")
		header.Add("Vary", "Origin")
	}
	// Checked after the CORS headers so a disabled console still produces a
	// readable error in the browser instead of an opaque network failure.
	if !router.adminEnabled() {
		writeError(writer, request, http.StatusServiceUnavailable, "SERVER_ERROR", "admin console unavailable")
		return
	}

	path := strings.TrimPrefix(request.URL.Path, adminPathPrefix)
	if path == "/auth/login" || path == "/auth/mfa" {
		if request.Method != http.MethodPost {
			writeError(writer, request, http.StatusMethodNotAllowed, "INVALID_REQUEST", "method not allowed")
			return
		}
		if path == "/auth/login" {
			router.handleAdminLogin(writer, request)
		} else {
			router.handleAdminMFA(writer, request)
		}
		return
	}

	session, account, token, ok := router.authenticateAdmin(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		if !router.verifyAdminCSRF(request, token) {
			router.recordSecurityEvent(request, account, "ADMIN_CSRF_REJECTED", "warning", map[string]string{"path": request.URL.Path})
			writeError(writer, request, http.StatusForbidden, "CSRF_REJECTED", "csrf token rejected")
			return
		}
	}
	if !account.MFAEnrolled && !adminEnrollmentExempt(path, request.Method) {
		writeError(writer, request, http.StatusForbidden, "MFA_ENROLLMENT_REQUIRED", "multi-factor authentication enrollment is required")
		return
	}
	router.routeAdmin(writer, request, session, account, path)
}

// adminEnrollmentExempt lists the routes an unenrolled administrator may
// still reach: identity endpoints plus the enrollment flow itself.
func adminEnrollmentExempt(path string, method string) bool {
	switch {
	case path == "/auth/logout" && method == http.MethodPost:
	case path == "/me" && method == http.MethodGet:
	case path == "/mfa/enroll/start" && method == http.MethodPost:
	case path == "/mfa/enroll/confirm" && method == http.MethodPost:
	default:
		return false
	}
	return true
}

func (router *Router) routeAdmin(writer http.ResponseWriter, request *http.Request, session *domain.AdminSession, account *domain.AdminAccount, path string) {
	segments := splitAdminPath(path)
	switch {
	case len(segments) == 2 && segments[0] == "auth" && segments[1] == "logout":
		if request.Method != http.MethodPost {
			writeError(writer, request, http.StatusMethodNotAllowed, "INVALID_REQUEST", "method not allowed")
			return
		}
		router.handleAdminLogout(writer, request, session, token(request))
	case len(segments) == 1 && segments[0] == "me" && request.Method == http.MethodGet:
		router.handleAdminMe(writer, request, account)
	case len(segments) == 3 && segments[0] == "mfa" && segments[1] == "enroll" && segments[2] == "start" && request.Method == http.MethodPost:
		router.handleAdminMFAEnrollStart(writer, request, account)
	case len(segments) == 3 && segments[0] == "mfa" && segments[1] == "enroll" && segments[2] == "confirm" && request.Method == http.MethodPost:
		router.handleAdminMFAEnrollConfirm(writer, request, account)
	case len(segments) == 2 && segments[0] == "mfa" && segments[1] == "disable" && request.Method == http.MethodPost:
		router.handleAdminMFADisable(writer, request, account)
	case len(segments) == 2 && segments[0] == "overview" && segments[1] == "stats" && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermOverviewRead) {
			return
		}
		router.handleAdminOverviewStats(writer, request)
	case len(segments) == 1 && segments[0] == "overview" && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermOverviewRead) {
			return
		}
		router.handleAdminOverview(writer, request, account)
	case len(segments) >= 1 && segments[0] == "users":
		router.routeAdminUsers(writer, request, account, segments)
	case len(segments) >= 1 && segments[0] == "licenses":
		router.routeAdminLicenses(writer, request, account, segments)
	case len(segments) >= 1 && segments[0] == "devices":
		router.routeAdminDevices(writer, request, account, segments)
	case len(segments) >= 1 && segments[0] == "sessions":
		router.routeAdminSessions(writer, request, account, segments)
	case len(segments) == 1 && segments[0] == "audit-logs" && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermAuditRead) {
			return
		}
		router.handleAdminAuditLogs(writer, request)
	case len(segments) == 1 && segments[0] == "security-events" && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermSecurityRead) {
			return
		}
		router.handleAdminSecurityEvents(writer, request)
	case len(segments) == 1 && segments[0] == "roles" && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermAdminsRead) {
			return
		}
		router.handleAdminRoles(writer, request)
	case len(segments) >= 1 && segments[0] == "admins":
		router.routeAdminAccounts(writer, request, account, segments)
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
}

// requirePermission enforces RBAC data-driven: the check only consults the
// account's permission set, never role names.
func (router *Router) requirePermission(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, permission string) bool {
	if account.HasPermission(permission) {
		return true
	}
	router.recordSecurityEvent(request, account, "ADMIN_PERMISSION_DENIED", "warning", map[string]string{
		"permission": permission,
		"path":       request.URL.Path,
	})
	writeError(writer, request, http.StatusForbidden, "PERMISSION_DENIED", "permission denied")
	return false
}

func token(request *http.Request) string {
	cookie, err := request.Cookie(adminSessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func splitAdminPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// authenticateAdmin resolves the session cookie to an active admin session.
func (router *Router) authenticateAdmin(writer http.ResponseWriter, request *http.Request) (*domain.AdminSession, *domain.AdminAccount, string, bool) {
	cookie, err := request.Cookie(adminSessionCookieName)
	if err != nil || cookie.Value == "" {
		writeError(writer, request, http.StatusUnauthorized, "ADMIN_UNAUTHENTICATED", "authentication required")
		return nil, nil, "", false
	}
	session, account, err := router.admin.Auth.Authenticate(request.Context(), cookie.Value)
	if err != nil {
		clearAdminCookies(writer, router.admin.CookieSecure)
		writeError(writer, request, http.StatusUnauthorized, "ADMIN_UNAUTHENTICATED", "authentication required")
		return nil, nil, "", false
	}
	return session, account, cookie.Value, true
}

// adminCSRFToken derives a session-bound CSRF token; the double-submit cookie
// value and the expected header value share this derivation.
func (router *Router) adminCSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, router.admin.CSRFSecret)
	mac.Write([]byte("admin-csrf|" + sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

func (router *Router) verifyAdminCSRF(request *http.Request, sessionToken string) bool {
	expected := router.adminCSRFToken(sessionToken)
	provided := request.Header.Get(adminCSRFHeader)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// auditAdmin appends one audit record for a console action. Audit failures
// never break the primary operation because the action already happened.
func (router *Router) auditAdmin(request *http.Request, account *domain.AdminAccount, action, resourceType, resourceID string, metadata any) {
	entry := domain.NewAuditLog{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPSHA256:     hashClientIP(request, router.trustedProxies),
		UserAgent:    truncateAdminUserAgent(request.UserAgent()),
	}
	if account != nil {
		entry.AdminAccountID = account.ID
		entry.ActorEmail = account.Email
	}
	if metadata != nil {
		if raw, err := jsonMarshal(metadata); err == nil {
			entry.Metadata = raw
		}
	}
	_ = router.admin.Console.AppendAuditLog(request.Context(), entry)
}

// recordSecurityEvent appends one security event; failures are swallowed so
// anomaly tracking can never break the primary operation.
func (router *Router) recordSecurityEvent(request *http.Request, account *domain.AdminAccount, kind, severity string, metadata any) {
	entry := domain.NewSecurityEvent{
		Kind:      kind,
		Severity:  severity,
		IPSHA256:  hashClientIP(request, router.trustedProxies),
		UserAgent: truncateAdminUserAgent(request.UserAgent()),
	}
	if account != nil {
		entry.AdminAccountID = account.ID
		entry.ActorEmail = account.Email
	}
	if metadata != nil {
		if raw, err := jsonMarshal(metadata); err == nil {
			entry.Metadata = raw
		}
	}
	_ = router.admin.Console.AppendSecurityEvent(request.Context(), entry)
}

func (router *Router) writeConsoleError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		writeError(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		writeError(writer, request, http.StatusConflict, "USER_ALREADY_EXISTS", "a user with this email already exists")
	case errors.Is(err, domain.ErrLicenseNotFound):
		writeError(writer, request, http.StatusNotFound, "LICENSE_NOT_FOUND", "license not found")
	case errors.Is(err, domain.ErrLicenseAlreadyExists):
		writeError(writer, request, http.StatusConflict, "LICENSE_ALREADY_EXISTS", "license already exists for user and product")
	case errors.Is(err, domain.ErrDeviceNotFound):
		writeError(writer, request, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
	case errors.Is(err, domain.ErrAuthSessionNotFound):
		writeError(writer, request, http.StatusNotFound, "SESSION_NOT_FOUND", "session not found")
	case errors.Is(err, domain.ErrAdminNotFound):
		writeError(writer, request, http.StatusNotFound, "ADMIN_NOT_FOUND", "admin not found")
	case errors.Is(err, domain.ErrAdminAlreadyExists):
		writeError(writer, request, http.StatusConflict, "ADMIN_ALREADY_EXISTS", "an admin account with this email already exists")
	case errors.Is(err, domain.ErrRoleNotFound):
		writeError(writer, request, http.StatusBadRequest, "ROLE_NOT_FOUND", "role not found")
	default:
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
	}
}
