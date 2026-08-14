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
	"strings"
	"time"

	"github.com/starloader/backend/internal/domain"
)

const (
	adminSessionCookieName = "starloader_admin_session"
	adminCSRFCookieName    = "starloader_admin_csrf"
	adminCSRFHeader        = "X-CSRF-Token"
	adminPathPrefix        = "/v1/admin"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AdminAuthService authenticates dashboard administrators.
type AdminAuthService interface {
	Login(ctx context.Context, email, password, ipAddress, userAgent string) (string, *domain.AdminAccount, error)
	Authenticate(ctx context.Context, token string) (*domain.AdminSession, *domain.AdminAccount, error)
	Logout(ctx context.Context, token string) error
}

// AdminConsoleStore is the persistence boundary for dashboard management.
type AdminConsoleStore interface {
	ConsoleOverview(ctx context.Context) (*domain.ConsoleOverview, error)
	ListConsoleUsers(ctx context.Context, offset, limit int, search string) ([]domain.ConsoleUser, int64, error)
	ConsoleUserDetail(ctx context.Context, userID string) (*domain.ConsoleUserDetail, error)
	SetUserStatus(ctx context.Context, userID string, status domain.UserStatus) error
	FindUserByEmail(ctx context.Context, email string) (*domain.User, error)
	ListConsoleLicenses(ctx context.Context, offset, limit int) ([]domain.ConsoleLicense, int64, error)
	CreateLicense(ctx context.Context, input domain.NewLicense) (*domain.License, error)
	FindLicenseByID(ctx context.Context, licenseID string) (*domain.License, error)
	AdminUpdateLicense(ctx context.Context, licenseID string, expiresAt time.Time, maxDevices int) error
	AdminRevokeLicense(ctx context.Context, licenseID string) error
	ListConsoleDevices(ctx context.Context, offset, limit int) ([]domain.ConsoleDevice, int64, error)
	AdminRevokeDevice(ctx context.Context, deviceID string) error
	ListConsoleSessions(ctx context.Context, offset, limit int) ([]domain.ConsoleSession, int64, error)
	AdminRevokeAuthSession(ctx context.Context, sessionID string) error
	ListAuditLogs(ctx context.Context, offset, limit int) ([]domain.AuditLog, int64, error)
	AppendAuditLog(ctx context.Context, input domain.NewAuditLog) error
}

// AdminConfig bundles the dependencies of the /v1/admin namespace. The
// namespace stays disabled unless both Auth and Console are provided.
type AdminConfig struct {
	Auth           AdminAuthService
	Console        AdminConsoleStore
	LicenseHMACKey []byte
	Product        string
	AllowedOrigin  string
	CSRFSecret     []byte
	CookieSecure   bool
	SessionTTL     time.Duration
}

func (router *Router) adminEnabled() bool {
	return router.admin.Auth != nil && router.admin.Console != nil
}

func (router *Router) serveAdmin(writer http.ResponseWriter, request *http.Request) {
	if !router.adminEnabled() {
		writeError(writer, request, http.StatusServiceUnavailable, "SERVER_ERROR", "admin console unavailable")
		return
	}

	origin := request.Header.Get("Origin")
	originAllowed := origin != "" && origin == router.admin.AllowedOrigin
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

	path := strings.TrimPrefix(request.URL.Path, adminPathPrefix)
	if path == "/auth/login" {
		if request.Method != http.MethodPost {
			writeError(writer, request, http.StatusMethodNotAllowed, "INVALID_REQUEST", "method not allowed")
			return
		}
		router.handleAdminLogin(writer, request)
		return
	}

	session, account, token, ok := router.authenticateAdmin(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		if !router.verifyAdminCSRF(request, token) {
			writeError(writer, request, http.StatusForbidden, "CSRF_REJECTED", "csrf token rejected")
			return
		}
	}
	router.routeAdmin(writer, request, session, account, path)
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
	case len(segments) == 1 && segments[0] == "overview" && request.Method == http.MethodGet:
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
		router.handleAdminAuditLogs(writer, request)
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
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

func (router *Router) writeConsoleError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		writeError(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
	case errors.Is(err, domain.ErrLicenseNotFound):
		writeError(writer, request, http.StatusNotFound, "LICENSE_NOT_FOUND", "license not found")
	case errors.Is(err, domain.ErrLicenseAlreadyExists):
		writeError(writer, request, http.StatusConflict, "LICENSE_ALREADY_EXISTS", "license already exists for user and product")
	case errors.Is(err, domain.ErrDeviceNotFound):
		writeError(writer, request, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
	case errors.Is(err, domain.ErrAuthSessionNotFound):
		writeError(writer, request, http.StatusNotFound, "SESSION_NOT_FOUND", "session not found")
	default:
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
	}
}
